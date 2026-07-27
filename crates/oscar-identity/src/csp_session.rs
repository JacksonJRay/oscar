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
/// 1. Keychain access key + secret (+ optional session token for short-lived)
/// 2. Binary session: `aws sts get-caller-identity` succeeds with ambient config
/// 3. Else AuthRequest
pub fn resolve_aws_process_creds(
    profile: &Profile,
    binaries: &BinaryInventory,
) -> Result<ProcessCreds, AuthRequest> {
    if !binaries.has_aws() {
        return Err(auth_aws_missing_binary(profile));
    }

    // Keychain long-lived or short-lived
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
        // Avoid picking up conflicting profile
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

    // Ambient binary session (SSO / instance role / default chain) — allowed when detected.
    if aws_identity_ok(None) {
        let mut env = HashMap::new();
        if profile.label != "default" && !profile.label.is_empty() && !profile.label.contains(' ') {
            // Only set profile if named profile might exist; validation already ok ambient
            // Prefer not forcing wrong profile — use empty env for default chain.
        }
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

    Err(auth_aws_needed(profile, false))
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
    KeychainStore::set(
        &profile.secret_keyring_id,
        SecretKind::SessionToken,
        session_token,
    )?;
    if let Some(exp) = expires_at_unix {
        store_aws_session_expiry(profile, exp)?;
    }
    Ok(())
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
    let out = cmd
        .output()
        .map_err(|e| OscarError::Tool(format!("aws: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(OscarError::AuthRequired(err.trim().to_string()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
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
        Cloud::K8s => "Refresh kubeconfig or paste a valid kubeconfig into oscar keychain.",
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
        Cloud::K8s => vec!["kubectl config view".to_string()],
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
        "az login".to_string(),
        format!("oscar auth azure-sp --profile {}", profile.id),
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
