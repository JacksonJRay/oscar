//! Resolve CSP credentials: keychain long-lived, short-lived session tokens, or binary session.

use crate::binaries::BinaryInventory;
use crate::classify::{classify_auth_error, is_reauth_failure};
use crate::keychain::KeychainStore;
use crate::profiles::Profile;
use oscar_core::{AuthFailureKind, AuthRequest, AuthSource, Cloud, OscarError, OscarResult, SecretKind};
use std::collections::HashMap;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PROVIDER_KEY_PREFIX: &str = "oscar/provider";

/// Resolved env for a CSP CLI subprocess.
#[derive(Debug, Clone, Default)]
pub struct ProcessCreds {
    pub env: HashMap<String, String>,
    pub source: AuthSource,
    pub expires_at_unix: Option<u64>,
}

/// LLM provider API key resolution (never default env unless custom `api_key_env`).
pub fn store_provider_api_key(provider_id: &str, key: &str) -> OscarResult<()> {
    let id = format!("{PROVIDER_KEY_PREFIX}/{provider_id}");
    KeychainStore::set(&id, SecretKind::ApiKey, key)
}

pub fn load_provider_api_key(provider_id: &str) -> OscarResult<Option<String>> {
    let id = format!("{PROVIDER_KEY_PREFIX}/{provider_id}");
    KeychainStore::get(&id, SecretKind::ApiKey)
}

pub fn delete_provider_api_key(provider_id: &str) -> OscarResult<()> {
    let id = format!("{PROVIDER_KEY_PREFIX}/{provider_id}");
    KeychainStore::delete(&id, SecretKind::ApiKey)
}

/// Resolve AWS process credentials for CLI invocations.
///
/// Order:
/// 1. Keychain access key + secret (+ optional session token for short-lived) for **this** profile
/// 2. Ambient binary session only if it targets the same account (or profile has no fixed account)
/// 3. Else AuthRequest — never silently use ambient account A for profile bound to account B
pub fn resolve_aws_process_creds(
    profile: &Profile,
    binaries: &BinaryInventory,
) -> Result<ProcessCreds, AuthRequest> {
    if !binaries.has_aws() {
        return Err(auth_aws_missing_binary(profile));
    }

    // Keychain long-lived or short-lived (per-profile isolation)
    if let (Ok(Some(ak)), Ok(Some(sk))) = (
        KeychainStore::get(&profile.secret_keyring_id, SecretKind::AccessKeyId),
        KeychainStore::get(&profile.secret_keyring_id, SecretKind::SecretAccessKey),
    ) {
        let mut env = HashMap::new();
        env.insert("AWS_ACCESS_KEY_ID".into(), ak);
        env.insert("AWS_SECRET_ACCESS_KEY".into(), sk);
        let mut source = AuthSource::Keychain;
        if let Ok(Some(tok)) =
            KeychainStore::get(&profile.secret_keyring_id, SecretKind::SessionToken)
        {
            env.insert("AWS_SESSION_TOKEN".into(), tok);
            source = AuthSource::ShortLived;
        }
        // Avoid ambient profile/metadata clobbering keychain keys.
        // Do NOT set AWS_PROFILE="" — AWS CLI treats that as a real profile
        // name and fails with: "The config profile () could not be found".
        // Callers must clear AWS_PROFILE when spawning (see aws_runtime).
        env.insert("AWS_EC2_METADATA_DISABLED".into(), "true".into());
        if let Some(r) = &profile.default_region {
            env.insert("AWS_DEFAULT_REGION".into(), r.clone());
            env.insert("AWS_REGION".into(), r.clone());
        }
        return Ok(ProcessCreds {
            env,
            source,
            expires_at_unix: load_expiry(profile),
        });
    }

    // Ambient binary session only when safe for this multi-profile account binding.
    // Named labels (vdms, prod, …) must NOT silently inherit the shell's default
    // account — that made "aws-vdms" report 0 zones from the wrong account.
    if profile_allows_ambient_fallback(profile) {
        if let Some(ambient_account) = aws_caller_account(None) {
            if profile_allows_ambient_account(profile, &ambient_account) {
                let mut env = HashMap::new();
                if let Some(r) = &profile.default_region {
                    env.insert("AWS_DEFAULT_REGION".into(), r.clone());
                    env.insert("AWS_REGION".into(), r.clone());
                }
                return Ok(ProcessCreds {
                    env,
                    source: AuthSource::BinarySession,
                    expires_at_unix: None,
                });
            }
            // Ambient is a *different* account — require profile-scoped short-lived keys / SSO for this id.
            return Err(auth_aws_needed(profile, false).with_guidance(format!(
                "Ambient `aws` CLI is account `{ambient_account}`, but profile `{}` targets `{}`. \
                 Paste short-lived keys for this profile in the secure bar (bulk `export AWS_*` paste ok), \
                 or `oscar auth aws-session --profile {}`. Multi-account isolation: each oscar profile uses its own keychain namespace.",
                profile.id,
                profile.account_ref,
                profile.id
            )));
        }
    } else if let Some(ambient_account) = aws_caller_account(None) {
        // Named profile without keychain: explain instead of silent wrong-account scan.
        return Err(auth_aws_needed(profile, false).with_guidance(format!(
            "Profile `{}` (label `{}`) has no keychain keys. Ambient CLI is account `{ambient_account}` — \
             refusing to use it so we do not search the wrong account. \
             Paste STS/session keys in the secure bar (one block of export AWS_ACCESS_KEY_ID / SECRET / SESSION_TOKEN) \
             or run `oscar auth aws-session --profile {}`.",
            profile.id, profile.label, profile.id
        )));
    }

    Err(auth_aws_needed(profile, false))
}

/// True when profile is not pinned to a specific account id (ambient/default shell ok).
pub fn profile_has_fixed_account(profile: &Profile) -> bool {
    let a = profile.account_ref.trim().to_ascii_lowercase();
    !a.is_empty()
        && a != "pending"
        && a != "unknown"
        && a != "ambient"
        && a != "default"
        && a != "n/a"
}

/// Ambient shell credentials are only allowed for default/ambient-style profiles.
/// Named multi-account labels always need profile-scoped keychain secrets.
pub fn profile_allows_ambient_fallback(profile: &Profile) -> bool {
    let label = profile.label.trim().to_ascii_lowercase();
    let id = profile.id.trim().to_ascii_lowercase();
    matches!(
        label.as_str(),
        "default" | "ambient" | "local" | "shell" | ""
    ) || id == "aws-default"
        || id == "aws-ambient"
        || id.ends_with("-default")
        || id.ends_with("-ambient")
}

fn profile_allows_ambient_account(profile: &Profile, ambient_account: &str) -> bool {
    if !profile_allows_ambient_fallback(profile) {
        return false;
    }
    if !profile_has_fixed_account(profile) {
        return true;
    }
    profile.account_ref.trim() == ambient_account.trim()
}

/// True when text looks like chat/transcript rather than a secret value.
pub fn looks_like_transcript_not_secret(s: &str) -> bool {
    let low = s.to_ascii_lowercase();
    // Full-chat copies often start with role prefixes or tool chrome.
    if low.starts_with("user:")
        || low.starts_with("assistant:")
        || low.starts_with("thinking:")
        || low.starts_with("tool:")
        || low.starts_with("error:")
        || low.starts_with("notice:")
    {
        return true;
    }
    let hits = [
        "user: ",
        "assistant: ",
        "thinking: ",
        "tool: ◆",
        "credentials needed",
        "secure bar",
        "✓ done",
    ]
    .iter()
    .filter(|p| low.contains(*p))
    .count();
    hits >= 2 || s.lines().count() > 8 && hits >= 1
}

/// Shape-check an AWS secret before writing to the durable store.
/// Rejects chat transcripts and obviously wrong lengths so a bad paste cannot
/// poison a previously valid key set.
pub fn validate_aws_secret_value(kind: SecretKind, value: &str) -> Result<(), String> {
    let v = value.trim();
    if v.is_empty() {
        return Err("empty secret".into());
    }
    if looks_like_transcript_not_secret(v) {
        return Err(
            "paste looks like chat/transcript, not credentials — copy only the export AWS_* block into the secure bar"
                .into(),
        );
    }
    match kind {
        SecretKind::AccessKeyId => {
            // AKIA (long-lived) / ASIA (STS) / AROA etc. — keep loose but length-bound.
            if v.len() < 16 || v.len() > 128 {
                return Err(format!(
                    "AWS access key id has unexpected length {} (expected 16–128)",
                    v.len()
                ));
            }
            if v.contains('\n') || v.contains(' ') {
                return Err("AWS access key id must be a single token (no spaces/newlines)".into());
            }
            let ok_prefix = v.starts_with("AKIA")
                || v.starts_with("ASIA")
                || v.starts_with("AROA")
                || v.starts_with("AIDA")
                || v.chars().all(|c| c.is_ascii_alphanumeric());
            if !ok_prefix {
                return Err("AWS access key id has unexpected shape".into());
            }
        }
        SecretKind::SecretAccessKey => {
            if v.len() < 20 || v.len() > 128 {
                return Err(format!(
                    "AWS secret access key has unexpected length {} (expected 20–128)",
                    v.len()
                ));
            }
            if v.contains('\n') {
                return Err("AWS secret access key must be a single line".into());
            }
        }
        SecretKind::SessionToken => {
            if v.len() < 20 || v.len() > 4096 {
                return Err(format!(
                    "AWS session token has unexpected length {} (expected 20–4096)",
                    v.len()
                ));
            }
            // Tokens are long base64-ish; reject multi-paragraph pastes.
            if v.lines().count() > 3 {
                return Err("AWS session token has too many lines".into());
            }
        }
        _ => {}
    }
    Ok(())
}

/// Whether the profile has durable AWS access+secret keys stored (file/keychain).
/// Does not call STS — used to stop prepare→auth loops after a successful paste.
pub fn profile_has_stored_aws_keys(profile: &Profile) -> bool {
    let ak = KeychainStore::get(&profile.secret_keyring_id, SecretKind::AccessKeyId)
        .ok()
        .flatten();
    let sk = KeychainStore::get(&profile.secret_keyring_id, SecretKind::SecretAccessKey)
        .ok()
        .flatten();
    match (ak, sk) {
        (Some(a), Some(s)) => {
            validate_aws_secret_value(SecretKind::AccessKeyId, &a).is_ok()
                && validate_aws_secret_value(SecretKind::SecretAccessKey, &s).is_ok()
        }
        _ => false,
    }
}

/// Parse shell-style AWS credential exports from a secure-bar paste.
/// Supports multi-line `export AWS_ACCESS_KEY_ID=…` blocks (and KEY=value without export).
/// Returns only recognized, shape-validated fields; never logs values.
pub fn parse_aws_env_exports(paste: &str) -> Vec<(SecretKind, String)> {
    // Reject whole-chat pastes early (common when click-copy dumps the transcript).
    if looks_like_transcript_not_secret(paste) && !paste.contains("AWS_ACCESS_KEY_ID") {
        return Vec::new();
    }
    let mut map: HashMap<String, String> = HashMap::new();
    for raw_line in paste.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export ")
            .or_else(|| line.strip_prefix("Export "))
            .unwrap_or(line)
            .trim();
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_uppercase();
        let mut val = v.trim().to_string();
        // Strip matching quotes
        if (val.starts_with('"') && val.ends_with('"'))
            || (val.starts_with('\'') && val.ends_with('\''))
        {
            val = val[1..val.len() - 1].to_string();
        }
        if !val.is_empty() {
            map.insert(key, val);
        }
    }
    // Also accept single-line whitespace-separated export forms (rare).
    if map.is_empty() {
        for part in paste.split_whitespace() {
            let part = part
                .strip_prefix("export")
                .map(|s| s.trim_start_matches(|c: char| c == '=' || c.is_whitespace()))
                .unwrap_or(part);
            if let Some((k, v)) = part.split_once('=') {
                let key = k.trim().to_ascii_uppercase();
                if key.starts_with("AWS_") && !v.is_empty() {
                    map.insert(key, v.trim_matches(|c| c == '"' || c == '\'').to_string());
                }
            }
        }
    }
    let mut out = Vec::new();
    if let Some(v) = map.remove("AWS_ACCESS_KEY_ID") {
        if validate_aws_secret_value(SecretKind::AccessKeyId, &v).is_ok() {
            out.push((SecretKind::AccessKeyId, v));
        }
    }
    if let Some(v) = map.remove("AWS_SECRET_ACCESS_KEY") {
        if validate_aws_secret_value(SecretKind::SecretAccessKey, &v).is_ok() {
            out.push((SecretKind::SecretAccessKey, v));
        }
    }
    if let Some(v) = map.remove("AWS_SESSION_TOKEN") {
        if validate_aws_secret_value(SecretKind::SessionToken, &v).is_ok() {
            out.push((SecretKind::SessionToken, v));
        }
    }
    out
}

/// After successful STS, pin profile.account_ref when it was pending/unknown.
pub fn bind_aws_account_ref_if_pending(profile: &Profile, account_id: &str) -> OscarResult<bool> {
    let account_id = account_id.trim();
    if account_id.is_empty() {
        return Ok(false);
    }
    if profile_has_fixed_account(profile) && profile.account_ref.trim() == account_id {
        return Ok(false);
    }
    if profile_has_fixed_account(profile) {
        // Already pinned to a different id — do not overwrite silently.
        return Ok(false);
    }
    let paths = oscar_core::Paths::discover()?;
    let mut store = crate::profiles::ProfileStore::load(&paths)?;
    let Some(existing) = store.get(&profile.id).cloned() else {
        return Ok(false);
    };
    let mut updated = existing;
    updated.account_ref = account_id.to_string();
    store.upsert(updated);
    store.save()?;
    Ok(true)
}

/// Account id from ambient or env-scoped `aws sts get-caller-identity` (no secrets).
fn aws_caller_account(extra_env: Option<&HashMap<String, String>>) -> Option<String> {
    let mut cmd = Command::new("aws");
    cmd.args(["sts", "get-caller-identity", "--output", "json"]);
    if let Some(env) = extra_env {
        for (k, v) in env {
            cmd.env(k, v);
        }
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    v.get("Account")
        .and_then(|a| a.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn load_expiry(profile: &Profile) -> Option<u64> {
    KeychainStore::get(&profile.secret_keyring_id, SecretKind::Other)
        .ok()
        .flatten()
        .and_then(|s| {
            s.strip_prefix("expires_at=")
                .and_then(|n| n.parse().ok())
        })
}

pub fn store_aws_session_expiry(profile: &Profile, expires_at_unix: u64) -> OscarResult<()> {
    KeychainStore::set(
        &profile.secret_keyring_id,
        SecretKind::Other,
        &format!("expires_at={expires_at_unix}"),
    )
}

/// Store short-lived AWS keys (from STS assume-role or pasted temp creds).
pub fn store_aws_short_lived(
    profile: &Profile,
    access_key_id: &str,
    secret_access_key: &str,
    session_token: &str,
    expires_at_unix: Option<u64>,
) -> OscarResult<()> {
    for (kind, val) in [
        (SecretKind::AccessKeyId, access_key_id),
        (SecretKind::SecretAccessKey, secret_access_key),
        (SecretKind::SessionToken, session_token),
    ] {
        if let Err(e) = validate_aws_secret_value(kind, val) {
            return Err(OscarError::Config(format!("invalid {kind:?}: {e}")));
        }
    }
    KeychainStore::set(
        &profile.secret_keyring_id,
        SecretKind::AccessKeyId,
        access_key_id.trim(),
    )?;
    KeychainStore::set(
        &profile.secret_keyring_id,
        SecretKind::SecretAccessKey,
        secret_access_key.trim(),
    )?;
    KeychainStore::set(
        &profile.secret_keyring_id,
        SecretKind::SessionToken,
        session_token.trim(),
    )?;
    if let Some(exp) = expires_at_unix {
        store_aws_session_expiry(profile, exp)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::SecretKind;

    #[test]
    fn parse_aws_export_block() {
        let paste = r#"
export AWS_ACCESS_KEY_ID=ASIAEXAMPLEKEY1234
export AWS_SECRET_ACCESS_KEY=secret/value+hereABCDEFGHijkl
export AWS_SESSION_TOKEN=FwoGZXIvYXdzEThisIsALongEnoughSessionTokenValueForValidation
"#;
        let fields = parse_aws_env_exports(paste);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].0, SecretKind::AccessKeyId);
        assert_eq!(fields[0].1, "ASIAEXAMPLEKEY1234");
        assert_eq!(fields[1].0, SecretKind::SecretAccessKey);
        assert_eq!(fields[2].0, SecretKind::SessionToken);
    }

    #[test]
    fn rejects_transcript_as_access_key() {
        let bad = "user: switch to vdms\nthinking: foo\ntool: ◆ system.access.prepare";
        assert!(looks_like_transcript_not_secret(bad));
        assert!(validate_aws_secret_value(SecretKind::AccessKeyId, bad).is_err());
    }

    #[test]
    fn named_profile_rejects_ambient_fallback() {
        let p = Profile::new(Cloud::Aws, "vdms", "pending");
        assert!(!profile_allows_ambient_fallback(&p));
        let d = Profile::new(Cloud::Aws, "default", "pending");
        assert!(profile_allows_ambient_fallback(&d));
    }
}

pub fn store_aws_long_lived(
    profile: &Profile,
    access_key_id: &str,
    secret_access_key: &str,
) -> OscarResult<()> {
    KeychainStore::set(
        &profile.secret_keyring_id,
        SecretKind::AccessKeyId,
        access_key_id,
    )?;
    KeychainStore::set(
        &profile.secret_keyring_id,
        SecretKind::SecretAccessKey,
        secret_access_key,
    )?;
    // Clear session token if any
    let _ = KeychainStore::delete(&profile.secret_keyring_id, SecretKind::SessionToken);
    Ok(())
}

fn aws_identity_ok(extra_env: Option<&HashMap<String, String>>) -> bool {
    let mut cmd = Command::new("aws");
    cmd.args(["sts", "get-caller-identity", "--output", "json"]);
    if let Some(env) = extra_env {
        for (k, v) in env {
            cmd.env(k, v);
        }
    }
    cmd.output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Validate AWS creds (keychain or ambient) and return account ARN snippet.
pub fn validate_aws(profile: &Profile, binaries: &BinaryInventory) -> OscarResult<String> {
    let creds = resolve_aws_process_creds(profile, binaries).map_err(|a| {
        OscarError::AuthRequired(format!("{} — {}", a.reason, a.hint_commands.join("; ")))
    })?;
    let mut cmd = Command::new("aws");
    cmd.args(["sts", "get-caller-identity", "--output", "json"]);
    for (k, v) in &creds.env {
        cmd.env(k, v);
    }
    // Explicit keys must not fight ambient AWS_PROFILE from the shell.
    if creds.env.contains_key("AWS_ACCESS_KEY_ID") {
        cmd.env_remove("AWS_PROFILE");
        cmd.env_remove("AWS_DEFAULT_PROFILE");
    }
    let out = cmd
        .output()
        .map_err(|e| OscarError::Tool(format!("aws: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(OscarError::AuthRequired(err.trim().to_string()));
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    // Pin pending account_ref after successful STS.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Some(acct) = v.get("Account").and_then(|a| a.as_str()) {
            let _ = bind_aws_account_ref_if_pending(profile, acct);
        }
    }
    Ok(text)
}

/// Attempt STS assume-role using current binary/keychain base, store short-lived into profile.
pub fn assume_role_into_profile(
    profile: &Profile,
    role_arn: &str,
    session_name: &str,
    binaries: &BinaryInventory,
) -> OscarResult<String> {
    if !binaries.has_aws() {
        return Err(OscarError::Tool("aws CLI not found".into()));
    }
    let base = resolve_aws_process_creds(profile, binaries).map_err(|a| {
        OscarError::AuthRequired(a.reason)
    })?;
    let mut cmd = Command::new("aws");
    cmd.args([
        "sts",
        "assume-role",
        "--role-arn",
        role_arn,
        "--role-session-name",
        session_name,
        "--output",
        "json",
    ]);
    for (k, v) in &base.env {
        cmd.env(k, v);
    }
    if base.env.contains_key("AWS_ACCESS_KEY_ID") {
        cmd.env_remove("AWS_PROFILE");
        cmd.env_remove("AWS_DEFAULT_PROFILE");
    }
    let out = cmd
        .output()
        .map_err(|e| OscarError::Tool(format!("sts assume-role: {e}")))?;
    if !out.status.success() {
        return Err(OscarError::Tool(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| OscarError::Tool(format!("assume-role json: {e}")))?;
    let creds = v
        .get("Credentials")
        .ok_or_else(|| OscarError::Tool("no Credentials in assume-role response".into()))?;
    let ak = creds
        .get("AccessKeyId")
        .and_then(|x| x.as_str())
        .ok_or_else(|| OscarError::Tool("missing AccessKeyId".into()))?;
    let sk = creds
        .get("SecretAccessKey")
        .and_then(|x| x.as_str())
        .ok_or_else(|| OscarError::Tool("missing SecretAccessKey".into()))?;
    let tok = creds
        .get("SessionToken")
        .and_then(|x| x.as_str())
        .ok_or_else(|| OscarError::Tool("missing SessionToken".into()))?;
    let exp = creds
        .get("Expiration")
        .and_then(|x| x.as_str())
        .and_then(parse_aws_expiration);
    store_aws_short_lived(profile, ak, sk, tok, exp)?;
    // Remember role
    let _ = KeychainStore::set(&profile.secret_keyring_id, SecretKind::RoleArn, role_arn);
    Ok(format!(
        "assumed {role_arn}; short-lived creds stored in keychain (source=short_lived)"
    ))
}

fn parse_aws_expiration(s: &str) -> Option<u64> {
    // Best-effort: if already unix
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    // Leave None if ISO parse not available without chrono in identity — store raw via Other optional
    let _ = SystemTime::now().duration_since(UNIX_EPOCH);
    None
}

pub fn auth_aws_needed(profile: &Profile, reauth: bool) -> AuthRequest {
    let mut req = AuthRequest::new(
        Cloud::Aws,
        if reauth {
            format!(
                "AWS credentials for profile `{}` are missing, invalid, or expired",
                profile.id
            )
        } else {
            format!(
                "AWS access required for profile `{}` (no keychain keys and no working binary session)",
                profile.id
            )
        },
        vec![
            SecretKind::AccessKeyId,
            SecretKind::SecretAccessKey,
            SecretKind::SessionToken,
        ],
    )
    .profile(profile.id.clone())
    .with_guidance(
        "Prefer short-lived creds: `aws sts assume-role` or SSO, then `oscar auth aws-session`, or paste temp keys. Long-lived access keys also accepted into keychain. Env AWS_* is not used unless you configure a custom provider env for LLMs.",
    )
    .with_hints([
        "aws sso login".to_string(),
        "aws sts get-caller-identity".to_string(),
        format!(
            "oscar auth aws-keys --profile {} --access-key-id … --secret-access-key …",
            profile.id
        ),
        format!(
            "oscar auth aws-session --profile {} --access-key-id … --secret-access-key … --session-token …",
            profile.id
        ),
        format!(
            "oscar auth aws-assume-role --profile {} --role-arn arn:aws:iam::…:role/…",
            profile.id
        ),
    ]);
    if reauth {
        req = req.reauth();
    }
    req
}

pub fn auth_aws_missing_binary(profile: &Profile) -> AuthRequest {
    AuthRequest::new(
        Cloud::Aws,
        "AWS CLI binary not found on PATH — install AWS CLI v2 so oscar can invoke it",
        vec![],
    )
    .profile(profile.id.clone())
    .with_guidance("Install https://docs.aws.amazon.com/cli/ and ensure `aws` is on PATH. oscar prefers detected binaries for CSP operations.")
    .with_hints(["which aws", "aws --version"])
}

/// Map a failed command error into optional AuthRequest for agent re-prompt.
pub fn auth_request_from_error(
    cloud: Cloud,
    profile_id: Option<&str>,
    error_text: &str,
) -> Option<AuthRequest> {
    let kind = classify_auth_error(error_text);
    if kind == AuthFailureKind::PermissionDenied {
        return None; // not a re-auth problem
    }
    if kind == AuthFailureKind::BinaryMissing {
        return Some(
            AuthRequest::new(cloud, error_text, vec![])
                .with_guidance("Install the CSP CLI binary and ensure it is on PATH.")
                .with_hints(match cloud {
                    Cloud::Aws => vec!["install AWS CLI v2".to_string()],
                    Cloud::Gcp => vec!["install Google Cloud SDK (gcloud)".to_string()],
                    Cloud::Azure => vec!["install Azure CLI (az)".to_string()],
                    Cloud::K8s => vec!["install kubectl".to_string()],
                    Cloud::Multi => vec![],
                }),
        );
    }
    if !is_reauth_failure(kind) && kind != AuthFailureKind::Other {
        return None;
    }
    // Treat ambiguous other with auth-ish keywords only when classify said expired/invalid/missing
    if kind == AuthFailureKind::Other {
        return None;
    }

    let kinds = match cloud {
        Cloud::Aws => vec![
            SecretKind::AccessKeyId,
            SecretKind::SecretAccessKey,
            SecretKind::SessionToken,
        ],
        Cloud::Gcp => vec![SecretKind::ServiceAccountJson],
        Cloud::Azure => vec![
            SecretKind::AzureTenantId,
            SecretKind::AzureClientId,
            SecretKind::AzureClientSecret,
        ],
        Cloud::K8s => vec![SecretKind::Kubeconfig],
        Cloud::Multi => vec![SecretKind::Other],
    };
    let mut req = AuthRequest::new(
        cloud,
        format!("Authentication failed ({kind:?}): {error_text}"),
        kinds,
    )
    .reauth()
    .with_guidance(match cloud {
        Cloud::Aws => "Re-authenticate with short-lived STS/SSO or paste new keys into oscar keychain.",
        Cloud::Gcp => "Run gcloud auth login / application-default, or store a service account JSON in oscar keychain.",
        Cloud::Azure => "Run az login or store service principal secrets in oscar keychain.",
        Cloud::K8s => {
            "Refresh cluster auth via system.cluster.prepare by kind: \
             EKS→AWS STS; GKE/AKS→cloud short-lived; kind/k3s/local→kubeconfig."
        }
        Cloud::Multi => "Re-authenticate the relevant cloud profile.",
    })
    .with_hints(match cloud {
        Cloud::Aws => vec![
            "aws sso login".to_string(),
            "oscar auth aws-session --profile …".to_string(),
        ],
        Cloud::Gcp => vec![
            "gcloud auth login".to_string(),
            "gcloud auth application-default login".to_string(),
        ],
        Cloud::Azure => vec!["az login".to_string()],
        Cloud::K8s => vec![
            "system.cluster.prepare cluster_kind=… label=…".to_string(),
            "kubectl config view".to_string(),
            "aws eks update-kubeconfig # when kind=eks".to_string(),
        ],
        Cloud::Multi => Vec::<String>::new(),
    });
    if let Some(id) = profile_id {
        req = req.profile(id);
    }
    Some(req)
}

pub fn resolve_gcp_hints(profile: &Profile, binaries: &BinaryInventory) -> Result<(), AuthRequest> {
    if !binaries.has_gcloud() {
        return Err(AuthRequest::new(
            Cloud::Gcp,
            "gcloud binary not found on PATH",
            vec![],
        )
        .profile(profile.id.clone())
        .with_hints(["install Google Cloud SDK"]));
    }
    // Binary session ok?
    let ok = Command::new("gcloud")
        .args(["auth", "print-access-token"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok {
        return Ok(());
    }
    // SA json in keychain
    if KeychainStore::has(&profile.secret_keyring_id, SecretKind::ServiceAccountJson) {
        return Ok(());
    }
    Err(AuthRequest::new(
        Cloud::Gcp,
        format!("GCP auth required for profile `{}`", profile.id),
        vec![SecretKind::ServiceAccountJson],
    )
    .profile(profile.id.clone())
    .with_guidance("Use gcloud user/ADC session (binary) or store service account JSON in oscar keychain.")
    .with_hints([
        "gcloud auth login".to_string(),
        "gcloud auth application-default login".to_string(),
        format!("oscar auth gcp-sa --profile {} --file sa.json", profile.id),
    ]))
}

pub fn resolve_azure_hints(profile: &Profile, binaries: &BinaryInventory) -> Result<(), AuthRequest> {
    if !binaries.has_az() {
        return Err(AuthRequest::new(
            Cloud::Azure,
            "az binary not found on PATH",
            vec![],
        )
        .profile(profile.id.clone()));
    }
    let ok = Command::new("az")
        .args(["account", "show"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok {
        return Ok(());
    }
    Err(AuthRequest::new(
        Cloud::Azure,
        format!("Azure auth required for profile `{}`", profile.id),
        vec![
            SecretKind::AzureTenantId,
            SecretKind::AzureClientId,
            SecretKind::AzureClientSecret,
        ],
    )
    .profile(profile.id.clone())
    .with_hints([
        "oscar auth az-login".to_string(),
        format!("oscar auth az-login --tenant <tenant-id>  # profile {}", profile.id),
        "az account show".to_string(),
    ]))
}

pub fn resolve_k8s_hints(binaries: &BinaryInventory) -> Result<(), AuthRequest> {
    if !binaries.has_kubectl() {
        return Err(AuthRequest::new(
            Cloud::K8s,
            "kubectl binary not found on PATH",
            vec![],
        ));
    }
    let ok = Command::new("kubectl")
        .args(["cluster-info"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok {
        return Ok(());
    }
    Err(AuthRequest::new(
        Cloud::K8s,
        "Kubernetes access failed — refresh kubeconfig or credentials",
        vec![SecretKind::Kubeconfig],
    )
    .reauth()
    .with_hints(["kubectl config current-context", "aws eks update-kubeconfig …"]))
}
