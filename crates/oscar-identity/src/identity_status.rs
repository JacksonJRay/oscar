//! Non-secret inventory of identities / access oscar currently holds, with live validity checks.

use crate::binaries::BinaryInventory;
use crate::csp_session::{load_provider_api_key, resolve_aws_process_creds, validate_aws};
use crate::keychain::KeychainStore;
use crate::profiles::{Profile, ProfileStore};
use oscar_core::{AuthSource, Cloud, SecretKind};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// High-level validity of an identity path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Validity {
    /// Live probe succeeded.
    Valid,
    /// Keys present but expired or STS rejected.
    Expired,
    /// Configured but probe failed (wrong account, network, etc.).
    Invalid,
    /// No credentials found for this profile.
    Missing,
    /// Not probed yet / binary missing / indeterminate.
    Unknown,
}

impl Validity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Expired => "expired",
            Self::Invalid => "invalid",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
        }
    }

    pub fn glyph(self) -> &'static str {
        match self {
            Self::Valid => "OK",
            Self::Expired => "EXP",
            Self::Invalid => "BAD",
            Self::Missing => "---",
            Self::Unknown => "???",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    /// oscar profile (profiles.toml + keychain).
    Profile,
    /// Ambient CLI session not tied to a oscar profile.
    BinarySession,
    /// LLM provider API key in keychain.
    LlmProvider,
    /// Kubernetes context / cluster ref.
    Cluster,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEntry {
    pub kind: IdentityKind,
    /// Stable display id (profile id, provider id, context name).
    pub id: String,
    pub cloud: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// keychain | short_lived | binary_session | none | keychain_llm
    pub auth_source: String,
    /// Secret *kinds* present (never values).
    #[serde(default)]
    pub secrets_present: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<i64>,
    pub validity: Validity,
    /// Safe detail: ARN, email, project id — never secrets.
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub clusters: Vec<ClusterIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterIdentity {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub validity: Validity,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityInventory {
    pub checked_at_unix: u64,
    pub entries: Vec<IdentityEntry>,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl IdentityInventory {
    pub fn summary_line(&self) -> String {
        let mut ok = 0;
        let mut bad = 0;
        let mut miss = 0;
        for e in &self.entries {
            match e.validity {
                Validity::Valid => ok += 1,
                Validity::Missing => miss += 1,
                Validity::Expired | Validity::Invalid => bad += 1,
                Validity::Unknown => {}
            }
        }
        format!(
            "{} identities · {} valid · {} expired/invalid · {} missing",
            self.entries.len(),
            ok,
            bad,
            miss
        )
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn expiry_fields(exp: Option<u64>) -> (Option<u64>, Option<i64>, bool) {
    let now = now_unix();
    match exp {
        Some(e) => {
            let left = e as i64 - now as i64;
            (Some(e), Some(left), left <= 0)
        }
        None => (None, None, false),
    }
}

fn secret_kinds_present(keyring_id: &str) -> Vec<String> {
    let kinds = [
        SecretKind::AccessKeyId,
        SecretKind::SecretAccessKey,
        SecretKind::SessionToken,
        SecretKind::ServiceAccountJson,
        SecretKind::AzureClientId,
        SecretKind::AzureClientSecret,
        SecretKind::AzureTenantId,
        SecretKind::Kubeconfig,
        SecretKind::RoleArn,
        SecretKind::Other,
    ];
    kinds
        .iter()
        .filter(|k| KeychainStore::has(keyring_id, **k))
        .map(|k| format!("{k:?}").to_ascii_lowercase())
        .collect()
}

fn source_str(s: AuthSource) -> &'static str {
    match s {
        AuthSource::Keychain => "keychain",
        AuthSource::ShortLived => "short_lived",
        AuthSource::BinarySession => "binary_session",
        AuthSource::CustomEnv => "custom_env",
        AuthSource::HeadlessFlag => "headless",
        AuthSource::Unknown => "unknown",
    }
}

/// Full inventory with live probes (may take a few seconds).
pub fn build_identity_inventory(store: &ProfileStore, binaries: &BinaryInventory) -> IdentityInventory {
    let mut entries = Vec::new();
    let mut notes = Vec::new();
    let checked = now_unix();

    // LLM providers
    for provider in ["xai", "openai", "anthropic", "opencode-zen", "opencode-go"] {
        let has = matches!(load_provider_api_key(provider), Ok(Some(k)) if !k.is_empty());
        entries.push(IdentityEntry {
            kind: IdentityKind::LlmProvider,
            id: format!("llm/{provider}"),
            cloud: "llm".into(),
            label: provider.into(),
            account_ref: None,
            region: None,
            auth_source: if has {
                "keychain_llm".into()
            } else {
                "none".into()
            },
            secrets_present: if has {
                vec!["api_key".into()]
            } else {
                vec![]
            },
            expires_at_unix: None,
            expires_in_secs: None,
            validity: if has {
                Validity::Valid
            } else {
                Validity::Missing
            },
            detail: if has {
                "API key present in OS keychain (value hidden)".into()
            } else {
                "no key — oscar auth provider-key --provider …".into()
            },
            clusters: vec![],
        });
    }

    // Configured oscar profiles
    for p in store.list() {
        entries.push(probe_profile(p, binaries));
    }

    // Ambient binary sessions (when no profiles of that cloud, or always as extra rows)
    if binaries.has_aws() {
        let has_aws_profile = store.list().iter().any(|p| p.cloud == Cloud::Aws);
        if !has_aws_profile || ambient_aws_ok() {
            if let Some(e) = probe_ambient_aws(has_aws_profile) {
                // Avoid duplicate if we already have valid AWS profile covering same account
                let arn = e.detail.clone();
                let dup = entries.iter().any(|x| {
                    x.cloud == "aws"
                        && x.validity == Validity::Valid
                        && !arn.is_empty()
                        && x.detail.contains(arn.split('"').nth(3).unwrap_or(""))
                });
                if !dup || !has_aws_profile {
                    entries.push(e);
                }
            }
        }
    }
    if binaries.has_gcloud() {
        if let Some(e) = probe_ambient_gcp() {
            let has = store.list().iter().any(|p| p.cloud == Cloud::Gcp);
            if !has || e.validity == Validity::Valid {
                entries.push(e);
            }
        }
    }
    if binaries.has_az() {
        if let Some(e) = probe_ambient_azure() {
            let has = store.list().iter().any(|p| p.cloud == Cloud::Azure);
            if !has || e.validity == Validity::Valid {
                entries.push(e);
            }
        }
    }
    if binaries.has_kubectl() {
        for e in probe_kubectl_contexts() {
            entries.push(e);
        }
    } else {
        notes.push("kubectl not on PATH — k8s contexts not probed".into());
    }

    if store.list().is_empty() {
        notes.push(
            "No oscar profiles in ~/.config/oscar/profiles.toml — ambient CLI sessions still listed when available."
                .into(),
        );
    }

    IdentityInventory {
        checked_at_unix: checked,
        entries,
        notes,
    }
}

fn probe_profile(p: &Profile, binaries: &BinaryInventory) -> IdentityEntry {
    let secrets = secret_kinds_present(&p.secret_keyring_id);
    let mut clusters = Vec::new();
    for c in &p.clusters {
        clusters.push(probe_cluster_ref(c.name.as_str(), c.context.as_deref()));
    }

    match p.cloud {
        Cloud::Aws => probe_aws_profile(p, binaries, secrets, clusters),
        Cloud::Gcp => probe_gcp_profile(p, binaries, secrets, clusters),
        Cloud::Azure => probe_azure_profile(p, binaries, secrets, clusters),
        Cloud::K8s => {
            let mut entry = IdentityEntry {
                kind: IdentityKind::Profile,
                id: p.id.clone(),
                cloud: "k8s".into(),
                label: p.label.clone(),
                account_ref: Some(p.account_ref.clone()),
                region: p.default_region.clone(),
                auth_source: if secrets.is_empty() {
                    "none".into()
                } else {
                    "keychain".into()
                },
                secrets_present: secrets,
                expires_at_unix: None,
                expires_in_secs: None,
                validity: Validity::Unknown,
                detail: String::new(),
                clusters: clusters.clone(),
            };
            if let Some(ctx) = p.clusters.first().and_then(|c| c.context.clone()) {
                let c = probe_cluster_ref(p.label.as_str(), Some(&ctx));
                entry.validity = c.validity;
                entry.detail = c.detail;
            } else if binaries.has_kubectl() {
                entry.detail = "profile has no cluster context — attach kube context".into();
                entry.validity = Validity::Missing;
            } else {
                entry.detail = "kubectl missing".into();
            }
            entry
        }
        Cloud::Multi => IdentityEntry {
            kind: IdentityKind::Profile,
            id: p.id.clone(),
            cloud: "multi".into(),
            label: p.label.clone(),
            account_ref: Some(p.account_ref.clone()),
            region: p.default_region.clone(),
            auth_source: "none".into(),
            secrets_present: secrets,
            expires_at_unix: None,
            expires_in_secs: None,
            validity: Validity::Unknown,
            detail: "multi profile".into(),
            clusters,
        },
    }
}

fn probe_aws_profile(
    p: &Profile,
    binaries: &BinaryInventory,
    secrets: Vec<String>,
    clusters: Vec<ClusterIdentity>,
) -> IdentityEntry {
    let exp = KeychainStore::get(&p.secret_keyring_id, SecretKind::Other)
        .ok()
        .flatten()
        .and_then(|s| {
            s.strip_prefix("expires_at=")
                .and_then(|n| n.parse().ok())
        });
    let (expires_at_unix, expires_in_secs, expired_flag) = expiry_fields(exp);

    let mut entry = IdentityEntry {
        kind: IdentityKind::Profile,
        id: p.id.clone(),
        cloud: "aws".into(),
        label: p.label.clone(),
        account_ref: Some(p.account_ref.clone()),
        region: p.default_region.clone(),
        auth_source: "none".into(),
        secrets_present: secrets,
        expires_at_unix,
        expires_in_secs,
        validity: Validity::Missing,
        detail: String::new(),
        clusters,
    };

    if !binaries.has_aws() {
        entry.validity = Validity::Unknown;
        entry.detail = "aws CLI not on PATH".into();
        return entry;
    }

    match resolve_aws_process_creds(p, binaries) {
        Ok(creds) => {
            entry.auth_source = source_str(creds.source).into();
            if expired_flag && matches!(creds.source, AuthSource::ShortLived) {
                entry.validity = Validity::Expired;
                entry.detail = "session expiry timestamp is in the past — re-auth".into();
                return entry;
            }
            match validate_aws(p, binaries) {
                Ok(json) => {
                    entry.validity = Validity::Valid;
                    entry.detail = summarize_aws_identity(&json);
                    if let Some(acct) = extract_json_str(&json, "Account") {
                        entry.account_ref = Some(acct);
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.to_ascii_lowercase().contains("expired")
                        || msg.to_ascii_lowercase().contains("security token")
                    {
                        entry.validity = Validity::Expired;
                    } else {
                        entry.validity = Validity::Invalid;
                    }
                    entry.detail = truncate(&msg, 160);
                }
            }
        }
        Err(a) => {
            entry.validity = Validity::Missing;
            entry.detail = a.reason;
            entry.auth_source = "none".into();
        }
    }
    entry
}

fn probe_gcp_profile(
    p: &Profile,
    binaries: &BinaryInventory,
    secrets: Vec<String>,
    clusters: Vec<ClusterIdentity>,
) -> IdentityEntry {
    let mut entry = IdentityEntry {
        kind: IdentityKind::Profile,
        id: p.id.clone(),
        cloud: "gcp".into(),
        label: p.label.clone(),
        account_ref: Some(p.account_ref.clone()),
        region: p.default_region.clone(),
        auth_source: if secrets.iter().any(|s| s.contains("service_account")) {
            "keychain".into()
        } else {
            "binary_session".into()
        },
        secrets_present: secrets,
        expires_at_unix: None,
        expires_in_secs: None,
        validity: Validity::Unknown,
        detail: String::new(),
        clusters,
    };
    if !binaries.has_gcloud() {
        entry.detail = "gcloud not on PATH".into();
        return entry;
    }
    let project = if p.account_ref.is_empty() || p.account_ref == "unknown" {
        None
    } else {
        Some(p.account_ref.as_str())
    };
    match gcloud_active_account(project) {
        Ok(d) => {
            entry.validity = Validity::Valid;
            entry.detail = d;
            entry.auth_source = if entry.secrets_present.is_empty() {
                "binary_session".into()
            } else {
                entry.auth_source
            };
        }
        Err(e) => {
            entry.validity = if entry.secrets_present.is_empty() {
                Validity::Missing
            } else {
                Validity::Invalid
            };
            entry.detail = truncate(&e, 160);
        }
    }
    entry
}

fn probe_azure_profile(
    p: &Profile,
    binaries: &BinaryInventory,
    secrets: Vec<String>,
    clusters: Vec<ClusterIdentity>,
) -> IdentityEntry {
    let mut entry = IdentityEntry {
        kind: IdentityKind::Profile,
        id: p.id.clone(),
        cloud: "azure".into(),
        label: p.label.clone(),
        account_ref: Some(p.account_ref.clone()),
        region: p.default_region.clone(),
        auth_source: if secrets.iter().any(|s| s.contains("azure")) {
            "keychain".into()
        } else {
            "binary_session".into()
        },
        secrets_present: secrets,
        expires_at_unix: None,
        expires_in_secs: None,
        validity: Validity::Unknown,
        detail: String::new(),
        clusters,
    };
    if !binaries.has_az() {
        entry.detail = "az not on PATH".into();
        return entry;
    }
    match az_account_show() {
        Ok(d) => {
            entry.validity = Validity::Valid;
            entry.detail = d;
        }
        Err(e) => {
            entry.validity = if entry.secrets_present.is_empty() {
                Validity::Missing
            } else {
                Validity::Invalid
            };
            entry.detail = truncate(&e, 160);
        }
    }
    entry
}

fn probe_ambient_aws(has_profile: bool) -> Option<IdentityEntry> {
    if !ambient_aws_ok() {
        if has_profile {
            return None;
        }
        return Some(IdentityEntry {
            kind: IdentityKind::BinarySession,
            id: "aws-ambient".into(),
            cloud: "aws".into(),
            label: "ambient CLI".into(),
            account_ref: None,
            region: None,
            auth_source: "binary_session".into(),
            secrets_present: vec![],
            expires_at_unix: None,
            expires_in_secs: None,
            validity: Validity::Missing,
            detail: "aws CLI present but sts get-caller-identity failed".into(),
            clusters: vec![],
        });
    }
    let json = Command::new("aws")
        .args(["sts", "get-caller-identity", "--output", "json"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;
    Some(IdentityEntry {
        kind: IdentityKind::BinarySession,
        id: "aws-ambient".into(),
        cloud: "aws".into(),
        label: "ambient CLI / SSO".into(),
        account_ref: extract_json_str(&json, "Account"),
        region: None,
        auth_source: "binary_session".into(),
        secrets_present: vec![],
        expires_at_unix: None,
        expires_in_secs: None,
        validity: Validity::Valid,
        detail: summarize_aws_identity(&json),
        clusters: vec![],
    })
}

fn ambient_aws_ok() -> bool {
    Command::new("aws")
        .args(["sts", "get-caller-identity", "--output", "json"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn probe_ambient_gcp() -> Option<IdentityEntry> {
    match gcloud_active_account(None) {
        Ok(d) => Some(IdentityEntry {
            kind: IdentityKind::BinarySession,
            id: "gcp-ambient".into(),
            cloud: "gcp".into(),
            label: "ambient gcloud".into(),
            account_ref: None,
            region: None,
            auth_source: "binary_session".into(),
            secrets_present: vec![],
            expires_at_unix: None,
            expires_in_secs: None,
            validity: Validity::Valid,
            detail: d,
            clusters: vec![],
        }),
        Err(e) => Some(IdentityEntry {
            kind: IdentityKind::BinarySession,
            id: "gcp-ambient".into(),
            cloud: "gcp".into(),
            label: "ambient gcloud".into(),
            account_ref: None,
            region: None,
            auth_source: "binary_session".into(),
            secrets_present: vec![],
            expires_at_unix: None,
            expires_in_secs: None,
            validity: Validity::Missing,
            detail: truncate(&e, 160),
            clusters: vec![],
        }),
    }
}

fn probe_ambient_azure() -> Option<IdentityEntry> {
    match az_account_show() {
        Ok(d) => Some(IdentityEntry {
            kind: IdentityKind::BinarySession,
            id: "azure-ambient".into(),
            cloud: "azure".into(),
            label: "ambient az".into(),
            account_ref: None,
            region: None,
            auth_source: "binary_session".into(),
            secrets_present: vec![],
            expires_at_unix: None,
            expires_in_secs: None,
            validity: Validity::Valid,
            detail: d,
            clusters: vec![],
        }),
        Err(e) => Some(IdentityEntry {
            kind: IdentityKind::BinarySession,
            id: "azure-ambient".into(),
            cloud: "azure".into(),
            label: "ambient az".into(),
            account_ref: None,
            region: None,
            auth_source: "binary_session".into(),
            secrets_present: vec![],
            expires_at_unix: None,
            expires_in_secs: None,
            validity: Validity::Missing,
            detail: truncate(&e, 160),
            clusters: vec![],
        }),
    }
}

fn probe_kubectl_contexts() -> Vec<IdentityEntry> {
    let out = Command::new("kubectl")
        .args(["config", "get-contexts", "-o", "name"])
        .output();
    let Ok(out) = out else {
        return vec![];
    };
    if !out.status.success() {
        return vec![IdentityEntry {
            kind: IdentityKind::Cluster,
            id: "k8s".into(),
            cloud: "k8s".into(),
            label: "kubectl".into(),
            account_ref: None,
            region: None,
            auth_source: "binary_session".into(),
            secrets_present: vec![],
            expires_at_unix: None,
            expires_in_secs: None,
            validity: Validity::Invalid,
            detail: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            clusters: vec![],
        }];
    }
    let names = String::from_utf8_lossy(&out.stdout);
    let mut entries = Vec::new();
    for name in names.lines().filter(|l| !l.trim().is_empty()) {
        let c = probe_cluster_ref(name, Some(name));
        entries.push(IdentityEntry {
            kind: IdentityKind::Cluster,
            id: format!("k8s/{name}"),
            cloud: "k8s".into(),
            label: name.into(),
            account_ref: None,
            region: None,
            auth_source: "kubeconfig".into(),
            secrets_present: vec![],
            expires_at_unix: None,
            expires_in_secs: None,
            validity: c.validity,
            detail: c.detail.clone(),
            clusters: vec![c],
        });
    }
    entries
}

fn probe_cluster_ref(name: &str, context: Option<&str>) -> ClusterIdentity {
    let ctx = context.unwrap_or(name);
    let mut cmd = Command::new("kubectl");
    cmd.args([
        "--context",
        ctx,
        "cluster-info",
        "--request-timeout=3s",
    ]);
    match cmd.output() {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            let endpoint = text
                .lines()
                .find(|l| l.contains("Kubernetes control plane") || l.contains("is running at"))
                .map(|l| l.trim().to_string())
                .unwrap_or_else(|| "cluster reachable".into());
            ClusterIdentity {
                name: name.into(),
                context: Some(ctx.into()),
                endpoint: Some(endpoint.clone()),
                validity: Validity::Valid,
                detail: truncate(&endpoint, 120),
            }
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            ClusterIdentity {
                name: name.into(),
                context: Some(ctx.into()),
                endpoint: None,
                validity: Validity::Invalid,
                detail: truncate(err.trim(), 120),
            }
        }
        Err(e) => ClusterIdentity {
            name: name.into(),
            context: Some(ctx.into()),
            endpoint: None,
            validity: Validity::Unknown,
            detail: format!("kubectl: {e}"),
        },
    }
}

fn gcloud_active_account(project: Option<&str>) -> Result<String, String> {
    let mut cmd = Command::new("gcloud");
    cmd.args(["auth", "list", "--filter=status:ACTIVE", "--format=json"]);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
    let account = v
        .as_array()
        .and_then(|a| a.first())
        .and_then(|x| x.get("account"))
        .and_then(|x| x.as_str())
        .unwrap_or("(no active account)");
    let mut detail = format!("account={account}");
    if let Some(proj) = project {
        let mut c2 = Command::new("gcloud");
        c2.args(["projects", "describe", proj, "--format=value(projectId)"]);
        if let Ok(o) = c2.output() {
            if o.status.success() {
                detail.push_str(&format!(" project={proj} (ok)"));
            } else {
                detail.push_str(&format!(
                    " project={proj} ({})",
                    String::from_utf8_lossy(&o.stderr).trim()
                ));
            }
        }
    } else {
        // current project
        if let Ok(o) = Command::new("gcloud")
            .args(["config", "get-value", "project"])
            .output()
        {
            let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !p.is_empty() && p != "(unset)" {
                detail.push_str(&format!(" project={p}"));
            }
        }
    }
    if account == "(no active account)" {
        return Err(detail);
    }
    Ok(detail)
}

fn az_account_show() -> Result<String, String> {
    let out = Command::new("az")
        .args(["account", "show", "-o", "json"])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
    let name = v
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or("?");
    let sub = v
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or("?");
    let user = v
        .pointer("/user/name")
        .and_then(|x| x.as_str())
        .unwrap_or("?");
    Ok(format!("sub={name} id={sub} user={user}"))
}

fn summarize_aws_identity(json: &str) -> String {
    let acct = extract_json_str(json, "Account").unwrap_or_default();
    let arn = extract_json_str(json, "Arn").unwrap_or_default();
    if arn.is_empty() {
        truncate(json, 120)
    } else {
        format!("account={acct} arn={arn}")
    }
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
}

fn truncate(s: &str, n: usize) -> String {
    let t = s.trim();
    if t.len() <= n {
        t.to_string()
    } else {
        format!("{}…", t.chars().take(n.saturating_sub(1)).collect::<String>())
    }
}

/// Quick inventory without live network probes (secrets presence + metadata only).
pub fn build_identity_inventory_quick(store: &ProfileStore) -> IdentityInventory {
    let mut entries = Vec::new();
    for provider in ["xai", "openai", "anthropic", "opencode-zen", "opencode-go"] {
        let has = matches!(load_provider_api_key(provider), Ok(Some(k)) if !k.is_empty());
        entries.push(IdentityEntry {
            kind: IdentityKind::LlmProvider,
            id: format!("llm/{provider}"),
            cloud: "llm".into(),
            label: provider.into(),
            account_ref: None,
            region: None,
            auth_source: if has { "keychain_llm".into() } else { "none".into() },
            secrets_present: if has { vec!["api_key".into()] } else { vec![] },
            expires_at_unix: None,
            expires_in_secs: None,
            validity: if has { Validity::Valid } else { Validity::Missing },
            detail: if has {
                "key present (not probed)".into()
            } else {
                "no key".into()
            },
            clusters: vec![],
        });
    }
    for p in store.list() {
        let secrets = secret_kinds_present(&p.secret_keyring_id);
        let exp = KeychainStore::get(&p.secret_keyring_id, SecretKind::Other)
            .ok()
            .flatten()
            .and_then(|s| s.strip_prefix("expires_at=").and_then(|n| n.parse().ok()));
        let (expires_at_unix, expires_in_secs, expired) = expiry_fields(exp);
        let validity = if secrets.is_empty() {
            Validity::Missing
        } else if expired {
            Validity::Expired
        } else {
            Validity::Unknown
        };
        entries.push(IdentityEntry {
            kind: IdentityKind::Profile,
            id: p.id.clone(),
            cloud: p.cloud.to_string(),
            label: p.label.clone(),
            account_ref: Some(p.account_ref.clone()),
            region: p.default_region.clone(),
            auth_source: if secrets.iter().any(|s| s.contains("session")) {
                "short_lived".into()
            } else if secrets.is_empty() {
                "none".into()
            } else {
                "keychain".into()
            },
            secrets_present: secrets,
            expires_at_unix,
            expires_in_secs,
            validity,
            detail: format!(
                "{} cluster(s) configured — press r to live-validate",
                p.clusters.len()
            ),
            clusters: p
                .clusters
                .iter()
                .map(|c| ClusterIdentity {
                    name: c.name.clone(),
                    context: c.context.clone(),
                    endpoint: None,
                    validity: Validity::Unknown,
                    detail: "not probed".into(),
                })
                .collect(),
        });
    }
    IdentityInventory {
        checked_at_unix: now_unix(),
        entries,
        notes: vec!["Quick view (no live probe). Press r / oscar identities check for validation.".into()],
    }
}
