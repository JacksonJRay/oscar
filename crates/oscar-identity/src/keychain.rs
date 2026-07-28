//! Oscar secret storage for cloud + LLM credentials.
//!
//! ## Why not only the OS keychain?
//!
//! We previously used the `keyring` crate (Linux → GNOME Secret Service / DBus)
//! exclusively. In practice on many Linux setups:
//!
//! 1. `set_password` returns **Ok** (or appears to succeed)
//! 2. A later process `get_password` returns **NoEntry** / empty
//! 3. The CLI still printed “stored in keychain” — so the user thought
//!    `aws-vdms` was authenticated, while tools saw **no secrets** and either
//!    refused ambient fallback (named profiles) or scanned the wrong account
//!
//! Common causes: locked login keyring, session vs login collection mismatch,
//! headless/agent sessions without a prompt unlock, or attribute mismatches in
//! secret-service.
//!
//! ## Oscar-native design
//!
//! **Primary / durable:** `~/.config/oscar/secrets/` files (dir `0700`, files
//! `0600`). Always written and always readable by oscar processes on the same
//! machine — no DBus, no unlock prompt.
//!
//! **Optional mirror:** OS keychain via `keyring` when available. Best-effort;
//! failures are logged and never fail the write path.
//!
//! Reads: file first (authoritative), then OS keychain (migration / external).

use oscar_core::{OscarError, OscarResult, Paths, SecretKind};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tracing::{debug, warn};

const SERVICE: &str = "oscar";

/// Cloud/LLM secret storage used by auth + tools.
///
/// Named `KeychainStore` for API stability; backend is oscar-native files
/// with optional OS keychain mirror.
pub struct KeychainStore;

impl KeychainStore {
    fn entry_user(profile_keyring_id: &str, kind: SecretKind) -> String {
        format!("{profile_keyring_id}/{}", kind_name(kind))
    }

    fn secrets_dir() -> OscarResult<PathBuf> {
        let paths = Paths::discover().map_err(|e| OscarError::Config(e.to_string()))?;
        let dir = paths.config_dir.join("secrets");
        fs::create_dir_all(&dir).map_err(|e| OscarError::Config(format!("secrets dir: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        Ok(dir)
    }

    fn file_path(profile_keyring_id: &str, kind: SecretKind) -> OscarResult<PathBuf> {
        // Flatten id into a single filename segment (no path traversal).
        let safe = format!("{profile_keyring_id}__{}", kind_name(kind))
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>();
        Ok(Self::secrets_dir()?.join(safe))
    }

    fn file_set(profile_keyring_id: &str, kind: SecretKind, secret: &str) -> OscarResult<()> {
        let path = Self::file_path(profile_keyring_id, kind)?;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&path)
            .map_err(|e| OscarError::Config(format!("secret file open: {e}")))?;
        f.write_all(secret.as_bytes())
            .map_err(|e| OscarError::Config(format!("secret file write: {e}")))?;
        f.sync_all()
            .map_err(|e| OscarError::Config(format!("secret file sync: {e}")))?;
        // Re-assert 0600 after write (some FS ignore open mode).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        debug!(path = %path.display(), "stored secret in oscar secrets dir");
        Ok(())
    }

    fn file_get(profile_keyring_id: &str, kind: SecretKind) -> OscarResult<Option<String>> {
        let path = Self::file_path(profile_keyring_id, kind)?;
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(&path)
            .map_err(|e| OscarError::Config(format!("secret file read: {e}")))?;
        if data.is_empty() {
            Ok(None)
        } else {
            Ok(Some(data))
        }
    }

    fn file_delete(profile_keyring_id: &str, kind: SecretKind) -> OscarResult<()> {
        let path = Self::file_path(profile_keyring_id, kind)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(OscarError::Config(format!("secret file delete: {e}"))),
        }
    }

    /// Store a secret. **Always** persists to oscar secrets dir; OS keychain is optional.
    pub fn set(profile_keyring_id: &str, kind: SecretKind, secret: &str) -> OscarResult<()> {
        // Authoritative write — must succeed for auth to be usable.
        Self::file_set(profile_keyring_id, kind, secret)?;

        let user = Self::entry_user(profile_keyring_id, kind);
        // Best-effort OS keychain mirror (never fail the call).
        match keyring::Entry::new(SERVICE, &user) {
            Ok(entry) => {
                if let Err(e) = entry.set_password(secret) {
                    warn!(%user, error = %e, "OS keyring mirror set failed (oscar file store ok)");
                } else {
                    debug!(%user, "mirrored secret to OS keychain");
                }
            }
            Err(e) => {
                warn!(%user, error = %e, "OS keyring entry unavailable (oscar file store ok)");
            }
        }
        Ok(())
    }

    /// Load a secret. Prefer oscar file store (authoritative), then OS keychain.
    pub fn get(profile_keyring_id: &str, kind: SecretKind) -> OscarResult<Option<String>> {
        if let Some(v) = Self::file_get(profile_keyring_id, kind)? {
            return Ok(Some(v));
        }

        // Migration path: secret only in OS keychain (older installs).
        let user = Self::entry_user(profile_keyring_id, kind);
        if let Ok(entry) = keyring::Entry::new(SERVICE, &user) {
            match entry.get_password() {
                Ok(p) if !p.is_empty() => {
                    // Promote into oscar store so future reads are reliable.
                    if let Err(e) = Self::file_set(profile_keyring_id, kind, &p) {
                        warn!(error = %e, "failed to promote OS keyring secret into file store");
                    }
                    return Ok(Some(p));
                }
                Ok(_) | Err(keyring::Error::NoEntry) => {}
                Err(e) => {
                    debug!(%user, error = %e, "OS keyring get failed");
                }
            }
        }
        Ok(None)
    }

    pub fn delete(profile_keyring_id: &str, kind: SecretKind) -> OscarResult<()> {
        let user = Self::entry_user(profile_keyring_id, kind);
        if let Ok(entry) = keyring::Entry::new(SERVICE, &user) {
            let _ = entry.delete_credential();
        }
        Self::file_delete(profile_keyring_id, kind)
    }

    pub fn has(profile_keyring_id: &str, kind: SecretKind) -> bool {
        matches!(Self::get(profile_keyring_id, kind), Ok(Some(_)))
    }

    /// Where secrets live (for doctor / status; never lists values).
    pub fn backend_summary() -> String {
        let dir = Paths::discover()
            .map(|p| p.config_dir.join("secrets").display().to_string())
            .unwrap_or_else(|_| "~/.config/oscar/secrets".into());
        format!("oscar secrets dir `{dir}` (0600) + optional OS keychain mirror")
    }
}

fn kind_name(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::ApiKey => "api_key",
        SecretKind::AccessKeyId => "access_key_id",
        SecretKind::SecretAccessKey => "secret_access_key",
        SecretKind::SessionToken => "session_token",
        SecretKind::ServiceAccountJson => "service_account_json",
        SecretKind::AzureClientSecret => "azure_client_secret",
        SecretKind::AzureClientId => "azure_client_id",
        SecretKind::AzureTenantId => "azure_tenant_id",
        SecretKind::Kubeconfig => "kubeconfig",
        SecretKind::RoleArn => "role_arn",
        SecretKind::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::SecretKind;

    #[test]
    fn oscar_secret_store_roundtrip() {
        let id = format!("oscar/test-{}", uuid::Uuid::new_v4());
        KeychainStore::set(&id, SecretKind::AccessKeyId, "AKIATEST").unwrap();
        let v = KeychainStore::get(&id, SecretKind::AccessKeyId).unwrap();
        assert_eq!(v.as_deref(), Some("AKIATEST"));
        assert!(KeychainStore::has(&id, SecretKind::AccessKeyId));
        KeychainStore::delete(&id, SecretKind::AccessKeyId).unwrap();
        assert!(KeychainStore::get(&id, SecretKind::AccessKeyId)
            .unwrap()
            .is_none());
    }
}
