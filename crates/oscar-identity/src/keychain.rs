use oscar_core::{OscarError, OscarResult, SecretKind};
use tracing::debug;

const SERVICE: &str = "oscar";

/// OS keychain-backed secret storage. Secrets never touch profile files.
pub struct KeychainStore;

impl KeychainStore {
    fn entry_user(profile_keyring_id: &str, kind: SecretKind) -> String {
        format!("{profile_keyring_id}/{}", kind_name(kind))
    }

    pub fn set(profile_keyring_id: &str, kind: SecretKind, secret: &str) -> OscarResult<()> {
        let user = Self::entry_user(profile_keyring_id, kind);
        let entry = keyring::Entry::new(SERVICE, &user)
            .map_err(|e| OscarError::Config(format!("keyring entry: {e}")))?;
        entry
            .set_password(secret)
            .map_err(|e| OscarError::Config(format!("keyring set: {e}")))?;
        debug!(%user, "stored secret in keychain");
        Ok(())
    }

    pub fn get(profile_keyring_id: &str, kind: SecretKind) -> OscarResult<Option<String>> {
        let user = Self::entry_user(profile_keyring_id, kind);
        let entry = keyring::Entry::new(SERVICE, &user)
            .map_err(|e| OscarError::Config(format!("keyring entry: {e}")))?;
        match entry.get_password() {
            Ok(p) => Ok(Some(p)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(OscarError::Config(format!("keyring get: {e}"))),
        }
    }

    pub fn delete(profile_keyring_id: &str, kind: SecretKind) -> OscarResult<()> {
        let user = Self::entry_user(profile_keyring_id, kind);
        let entry = keyring::Entry::new(SERVICE, &user)
            .map_err(|e| OscarError::Config(format!("keyring entry: {e}")))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(OscarError::Config(format!("keyring delete: {e}"))),
        }
    }

    pub fn has(profile_keyring_id: &str, kind: SecretKind) -> bool {
        matches!(Self::get(profile_keyring_id, kind), Ok(Some(_)))
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
