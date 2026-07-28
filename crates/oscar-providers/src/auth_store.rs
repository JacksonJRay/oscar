//! Unified LLM credential store (OpenCode-aligned).
//!
//! Secrets live in `~/.config/oscar/auth.json` (mode `0600`) as a map of
//! provider id → typed entry (`api` | `oauth`). API keys are dual-written to the
//! OS keychain under `oscar/provider/<id>` for backward compatibility.
//!
//! Never log or return key material to chat/transcripts.

use oscar_core::Paths;
use oscar_identity::{delete_provider_api_key, load_provider_api_key, store_provider_api_key};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Schema version written on save.
pub const AUTH_FILE_VERSION: u32 = 1;

/// Env override for entire auth map (CI / headless), OpenCode `OPENCODE_AUTH_CONTENT` parity.
pub const OSCAR_AUTH_CONTENT_ENV: &str = "OSCAR_AUTH_CONTENT";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub providers: BTreeMap<String, AuthEntry>,
}

fn default_version() -> u32 {
    AUTH_FILE_VERSION
}

/// Typed credential for one LLM provider (OpenCode `Auth.Info` shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthEntry {
    Api {
        key: String,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        metadata: BTreeMap<String, String>,
    },
    Oauth {
        /// Access token (bearer).
        access: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refresh: Option<String>,
        /// Unix seconds expiry of access token.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        updated_at: Option<u64>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        metadata: BTreeMap<String, String>,
    },
    /// Well-known / enterprise token blob (OpenCode parity; rarely used).
    Wellknown {
        key: String,
        token: String,
    },
}

impl AuthEntry {
    pub fn api_key(key: impl Into<String>) -> Self {
        Self::Api {
            key: key.into(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Api { .. } => "api",
            Self::Oauth { .. } => "oauth",
            Self::Wellknown { .. } => "wellknown",
        }
    }

    /// Secret material suitable as HTTP bearer / x-api-key (never log this).
    pub fn secret_for_request(&self) -> Option<&str> {
        match self {
            Self::Api { key, .. } => Some(key.as_str()),
            Self::Oauth { access, .. } => Some(access.as_str()),
            Self::Wellknown { token, .. } => Some(token.as_str()),
        }
    }

    pub fn is_empty_secret(&self) -> bool {
        self.secret_for_request()
            .map(|s| s.is_empty())
            .unwrap_or(true)
    }
}

/// Public status row (no secrets).
#[derive(Debug, Clone)]
pub struct AuthStatus {
    pub provider_id: String,
    pub kind: &'static str,
    pub has_secret: bool,
    pub expires: Option<u64>,
    pub email: Option<String>,
    pub auth_mode: Option<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn auth_path(paths: &Paths) -> &Path {
    &paths.auth_file
}

/// Load auth file. Supports:
/// - v1 typed entries
/// - legacy xAI-only map where each value is an OAuth session with `access_token`
/// - `OSCAR_AUTH_CONTENT` env JSON override
pub fn load(paths: &Paths) -> AuthFile {
    if let Ok(raw) = env::var(OSCAR_AUTH_CONTENT_ENV) {
        if !raw.trim().is_empty() {
            if let Ok(f) = parse_auth_json(&raw) {
                return f;
            }
        }
    }
    match fs::read_to_string(auth_path(paths)) {
        Ok(raw) => parse_auth_json(&raw).unwrap_or_default(),
        Err(_) => AuthFile::default(),
    }
}

pub fn parse_auth_json(raw: &str) -> Result<AuthFile, String> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("auth.json parse: {e}"))?;
    // Fast path: already v1 typed
    if let Ok(mut f) = serde_json::from_value::<AuthFile>(v.clone()) {
        if !f.providers.is_empty() || f.version > 0 {
            // If deserialize succeeded but entries might be empty wrong shape, check one
            if f.providers.values().all(|e| !matches_empty_placeholder(e)) {
                f.version = AUTH_FILE_VERSION;
                return Ok(f);
            }
        }
    }
    // Legacy: { "providers": { "xai": { "access_token": "…" } } }
    let mut file = AuthFile {
        version: AUTH_FILE_VERSION,
        providers: BTreeMap::new(),
    };
    let Some(map) = v.get("providers").and_then(|p| p.as_object()) else {
        // OpenCode flat map: { "openai": { "type": "api", "key": "…" } }
        if let Some(obj) = v.as_object() {
            for (k, val) in obj {
                if k == "version" {
                    continue;
                }
                if let Some(entry) = entry_from_value(val) {
                    file.providers.insert(k.clone(), entry);
                }
            }
        }
        return Ok(file);
    };
    for (k, val) in map {
        if let Some(entry) = entry_from_value(val) {
            file.providers.insert(k.clone(), entry);
        }
    }
    Ok(file)
}

fn matches_empty_placeholder(_e: &AuthEntry) -> bool {
    false
}

fn entry_from_value(val: &serde_json::Value) -> Option<AuthEntry> {
    if let Ok(e) = serde_json::from_value::<AuthEntry>(val.clone()) {
        return Some(e);
    }
    // Legacy OAuthSession (access_token field, no type)
    let access = val.get("access_token")?.as_str()?.to_string();
    if access.is_empty() {
        return None;
    }
    Some(AuthEntry::Oauth {
        access,
        refresh: val
            .get("refresh_token")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        expires: val.get("expires_at").and_then(|x| x.as_u64()),
        account_id: val
            .get("user_id")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        email: val
            .get("email")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        client_id: val
            .get("client_id")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        issuer: val
            .get("issuer")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        scope: val
            .get("scope")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        id_token: val
            .get("id_token")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        token_type: val
            .get("token_type")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        auth_mode: val
            .get("auth_mode")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        updated_at: val.get("updated_at").and_then(|x| x.as_u64()),
        metadata: BTreeMap::new(),
    })
}

/// Atomic write with mode 0600.
pub fn save(paths: &Paths, file: &AuthFile) -> Result<(), String> {
    paths.ensure().map_err(|e| e.to_string())?;
    let path = auth_path(paths);
    let mut out = file.clone();
    out.version = AUTH_FILE_VERSION;
    let raw = serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?;
    write_atomic(path, &raw)
}

fn write_atomic(path: &Path, raw: &str) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| format!("auth dir: {e}"))?;
    let tmp = path.with_extension(format!(
        "json.tmp.{}{}",
        std::process::id(),
        now_unix()
    ));
    fs::write(&tmp, raw).map_err(|e| format!("write auth tmp: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path).map_err(|e| format!("rename auth.json: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn get(paths: &Paths, provider_id: &str) -> Option<AuthEntry> {
    let id = normalize_auth_id(provider_id);
    let file = load(paths);
    file.providers
        .get(id)
        .cloned()
        .or_else(|| file.providers.get(provider_id).cloned())
}

pub fn set(paths: &Paths, provider_id: &str, entry: AuthEntry) -> Result<(), String> {
    set_with_mirror(paths, provider_id, entry, true)
}

/// Store credentials; when `mirror_keychain` is true, also write secret to OS keychain.
pub fn set_with_mirror(
    paths: &Paths,
    provider_id: &str,
    entry: AuthEntry,
    mirror_keychain: bool,
) -> Result<(), String> {
    let id = normalize_auth_id(provider_id).to_string();
    let mut file = load(paths);
    // Drop alias keys that would duplicate
    if id == "xai" {
        file.providers.remove("grok");
    }
    file.providers.insert(id.clone(), entry.clone());
    save(paths, &file)?;
    if mirror_keychain {
        if let Some(secret) = entry.secret_for_request() {
            if !secret.is_empty() {
                let _ = store_provider_api_key(&id, secret);
                if id == "xai" {
                    let _ = store_provider_api_key("grok", secret);
                }
            }
        }
    }
    debug!(provider = %id, kind = entry.kind_label(), "auth store set");
    Ok(())
}

pub fn set_api_key(paths: &Paths, provider_id: &str, key: &str) -> Result<(), String> {
    set_api_key_with_mirror(paths, provider_id, key, true)
}

/// Strip whitespace/newlines from pasted keys (shell/TTY paste often injects junk).
pub fn sanitize_api_key(key: &str) -> Result<String, String> {
    // Prefer first non-empty line so multi-line pastes of a single key still work.
    let line = key
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .trim();
    // Drop any remaining whitespace (Bearer headers reject control/space chars).
    let cleaned: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Err("empty API key".into());
    }
    if cleaned.chars().any(|c| c.is_control()) {
        return Err("API key contains invalid control characters".into());
    }
    // Heuristic: accidental shell prompt paste (e.g. "jackson@host:~$")
    if cleaned.contains(":$") || cleaned.contains("@") && cleaned.contains("://") {
        return Err("API key looks like shell prompt junk — paste only the key token".into());
    }
    Ok(cleaned)
}

pub fn set_api_key_with_mirror(
    paths: &Paths,
    provider_id: &str,
    key: &str,
    mirror_keychain: bool,
) -> Result<(), String> {
    let cleaned = sanitize_api_key(key)?;
    set_with_mirror(
        paths,
        provider_id,
        AuthEntry::api_key(cleaned),
        mirror_keychain,
    )
}

pub fn remove(paths: &Paths, provider_id: &str) -> Result<(), String> {
    let id = normalize_auth_id(provider_id).to_string();
    let mut file = load(paths);
    file.providers.remove(&id);
    if id == "xai" {
        file.providers.remove("grok");
        let _ = delete_provider_api_key("grok");
    }
    save(paths, &file)?;
    let _ = delete_provider_api_key(&id);
    let _ = delete_provider_api_key(provider_id);
    Ok(())
}

pub fn list_status(paths: &Paths) -> Vec<AuthStatus> {
    let file = load(paths);
    let mut out: Vec<AuthStatus> = Vec::new();
    for (id, e) in &file.providers {
        // Collapse xai → grok for display (one Grok provider)
        let display_id = if matches!(id.as_str(), "xai" | "x-ai" | "grok") {
            "grok"
        } else {
            id.as_str()
        };
        if out.iter().any(|s| s.provider_id == display_id) {
            continue;
        }
        let mut st = status_from_entry(display_id, e);
        st.provider_id = display_id.into();
        out.push(st);
    }
    // Keychain-only providers (not yet in auth.json)
    for id in ["grok", "openai", "anthropic", "opencode-zen", "opencode-go"] {
        if out.iter().any(|s| s.provider_id == id) {
            continue;
        }
        let has = matches!(load_provider_api_key(id), Ok(Some(k)) if !k.is_empty())
            || (id == "grok"
                && matches!(load_provider_api_key("xai"), Ok(Some(k)) if !k.is_empty()));
        if has {
            out.push(AuthStatus {
                provider_id: id.into(),
                kind: "keychain",
                has_secret: true,
                expires: None,
                email: None,
                auth_mode: None,
            });
        }
    }
    out.sort_by(|a, b| a.provider_id.cmp(&b.provider_id));
    out
}

fn status_from_entry(id: &str, e: &AuthEntry) -> AuthStatus {
    match e {
        AuthEntry::Oauth {
            expires,
            email,
            auth_mode,
            access,
            ..
        } => AuthStatus {
            provider_id: id.into(),
            kind: "oauth",
            has_secret: !access.is_empty(),
            expires: *expires,
            email: email.clone(),
            auth_mode: auth_mode.clone(),
        },
        AuthEntry::Api { key, .. } => AuthStatus {
            provider_id: id.into(),
            kind: "api",
            has_secret: !key.is_empty(),
            expires: None,
            email: None,
            auth_mode: None,
        },
        AuthEntry::Wellknown { token, .. } => AuthStatus {
            provider_id: id.into(),
            kind: "wellknown",
            has_secret: !token.is_empty(),
            expires: None,
            email: None,
            auth_mode: None,
        },
    }
}

/// Whether any credential exists for this provider (auth.json or keychain).
pub fn has_credentials(paths: &Paths, provider_id: &str) -> bool {
    let id = normalize_auth_id(provider_id);
    if let Some(e) = get(paths, id) {
        if !e.is_empty_secret() {
            return true;
        }
    }
    if matches!(load_provider_api_key(id), Ok(Some(k)) if !k.is_empty()) {
        return true;
    }
    if id == "xai" || id == "grok" {
        if matches!(load_provider_api_key("xai"), Ok(Some(k)) if !k.is_empty()) {
            return true;
        }
        if matches!(load_provider_api_key("grok"), Ok(Some(k)) if !k.is_empty()) {
            return true;
        }
    }
    false
}

/// Resolve a bearer/API secret for requests. Does not refresh OAuth (caller does).
pub fn resolve_static_secret(
    paths: &Paths,
    provider_id: &str,
    api_key_env: Option<&str>,
    allow_catalog_env: bool,
    catalog_env_names: &[&str],
) -> Result<String, String> {
    let id = normalize_auth_id(provider_id);

    if let Some(entry) = get(paths, id) {
        if let Some(s) = entry.secret_for_request() {
            if !s.is_empty() {
                return Ok(s.to_string());
            }
        }
    }

    // Keychain fallback / legacy
    if let Ok(Some(k)) = load_provider_api_key(id) {
        if !k.is_empty() {
            return Ok(k);
        }
    }
    if id == "xai" || id == "grok" {
        for alias in ["xai", "grok"] {
            if let Ok(Some(k)) = load_provider_api_key(alias) {
                if !k.is_empty() {
                    return Ok(k);
                }
            }
        }
    }

    if let Some(env_name) = api_key_env {
        if let Ok(v) = env::var(env_name) {
            if !v.is_empty() {
                return Ok(v);
            }
        }
        return Err(format!(
            "custom provider env `{env_name}` is set in config but empty/unset"
        ));
    }

    if allow_catalog_env {
        for name in catalog_env_names {
            if let Ok(v) = env::var(name) {
                if !v.is_empty() {
                    return Ok(v);
                }
            }
        }
    }

    Err(format!(
        "no credentials for provider `{id}`. Run: oscar auth connect {id}   or   oscar auth provider-key --provider {id}"
    ))
}

/// Canonical auth map key for aliases.
pub fn normalize_auth_id(id: &str) -> &str {
    match id {
        "grok" | "x-ai" | "xai-oauth" | "grok-oauth" | "xai-grok-oauth" => "xai",
        "claude" => "anthropic",
        "zen" => "opencode-zen",
        "go" => "opencode-go",
        other => other,
    }
}

/// Cache path helper for tests / catalog sharing.
pub fn config_cache_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("oscar"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_paths(dir: &Path) -> Paths {
        Paths {
            config_dir: dir.to_path_buf(),
            config_file: dir.join("config.toml"),
            profiles_file: dir.join("profiles.toml"),
            sessions_dir: dir.join("sessions"),
            artifacts_dir: dir.join("artifacts"),
            logs_dir: dir.join("logs"),
            mcp_credentials_file: dir.join("mcp_credentials.json"),
            auth_file: dir.join("auth.json"),
        }
    }

    #[test]
    fn api_key_roundtrip() {
        let tmp = tempdir().unwrap();
        let paths = test_paths(tmp.path());
        set_api_key(&paths, "openai", "sk-test-123").unwrap();
        let e = get(&paths, "openai").unwrap();
        assert_eq!(e.secret_for_request(), Some("sk-test-123"));
        assert_eq!(e.kind_label(), "api");
        let statuses = list_status(&paths);
        assert!(statuses.iter().any(|s| s.provider_id == "openai" && s.kind == "api"));
    }

    #[test]
    fn legacy_oauth_access_token_parse() {
        let raw = r#"{
          "providers": {
            "xai": {
              "access_token": "tok-legacy",
              "refresh_token": "ref",
              "expires_at": 9999999999,
              "client_id": "cid",
              "issuer": "https://auth.x.ai",
              "updated_at": 1,
              "auth_mode": "browser"
            }
          }
        }"#;
        let f = parse_auth_json(raw).unwrap();
        let e = f.providers.get("xai").unwrap();
        assert_eq!(e.secret_for_request(), Some("tok-legacy"));
        assert_eq!(e.kind_label(), "oauth");
    }

    #[test]
    fn typed_oauth_roundtrip() {
        let tmp = tempdir().unwrap();
        let paths = test_paths(tmp.path());
        set(
            &paths,
            "xai",
            AuthEntry::Oauth {
                access: "a".into(),
                refresh: Some("r".into()),
                expires: Some(now_unix() + 3600),
                account_id: None,
                email: Some("u@x.ai".into()),
                client_id: Some("c".into()),
                issuer: Some("https://auth.x.ai".into()),
                scope: None,
                id_token: None,
                token_type: Some("Bearer".into()),
                auth_mode: Some("device".into()),
                updated_at: Some(now_unix()),
                metadata: BTreeMap::new(),
            },
        )
        .unwrap();
        let raw = fs::read_to_string(&paths.auth_file).unwrap();
        assert!(raw.contains("\"type\": \"oauth\"") || raw.contains("\"type\":\"oauth\""));
        let e = get(&paths, "grok").unwrap(); // alias
        assert_eq!(e.secret_for_request(), Some("a"));
    }

    #[test]
    fn remove_clears_entry() {
        let tmp = tempdir().unwrap();
        let paths = test_paths(tmp.path());
        set_api_key(&paths, "anthropic", "sk-ant").unwrap();
        remove(&paths, "anthropic").unwrap();
        assert!(get(&paths, "anthropic").is_none());
    }
}
