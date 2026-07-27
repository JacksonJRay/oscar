//! Shared helpers for cloud discovery tools.

use crate::inventory::{
    dns_cache_path, load_json, network_cache_path, DnsInventory, NetworkInventory,
};
use oscar_core::{AuthRequest, Cloud, SecretKind};
use oscar_identity::{auth_aws_needed, Profile, ProfileStore};
use std::path::Path;

pub fn profiles_for_cloud<'a>(store: &'a ProfileStore, cloud: Cloud) -> Vec<&'a Profile> {
    store.list().iter().filter(|p| p.cloud == cloud).collect()
}

pub fn resolve_profiles<'a>(
    store: &'a ProfileStore,
    cloud: Cloud,
    profile_id: Option<&str>,
) -> Vec<&'a Profile> {
    if let Some(id) = profile_id {
        return store.get(id).into_iter().collect();
    }
    profiles_for_cloud(store, cloud)
}

/// Build a standard AuthRequest with CSP-specific kinds and operator hints.
pub fn auth_for(cloud: Cloud, reason: impl Into<String>) -> AuthRequest {
    auth_for_with_profile(cloud, None, reason)
}

/// AuthRequest tailored to an optional oscar profile id (fills concrete CLI hints).
pub fn auth_for_with_profile(
    cloud: Cloud,
    profile_id: Option<&str>,
    reason: impl Into<String>,
) -> AuthRequest {
    let reason = reason.into();
    let pid = profile_id.unwrap_or("<profile-id>");
    let mut req = match cloud {
        Cloud::Aws => AuthRequest::new(
            Cloud::Aws,
            reason,
            vec![
                SecretKind::AccessKeyId,
                SecretKind::SecretAccessKey,
                SecretKind::SessionToken,
            ],
        )
        .with_guidance(
            "Prefer short-lived creds. Paths: (1) `aws sso login` binary session, (2) `oscar auth aws-session` / aws-assume-role into this profile keychain, (3) long-lived keys via `oscar auth aws-keys` (least preferred). Ambient AWS_* env is not used by oscar tools.",
        )
        .with_hints(vec![
            format!("aws sso login  # then: oscar auth aws-test --profile {pid}"),
            format!("oscar auth aws-sso-login --profile {pid}"),
            format!(
                "oscar auth aws-session --profile {pid} --access-key-id … --secret-access-key … --session-token …"
            ),
            format!("oscar auth aws-assume-role --profile {pid} --role-arn arn:aws:iam::…:role/…"),
            format!("oscar auth aws-keys --profile {pid} --access-key-id … --secret-access-key …"),
            "TUI: paste short-lived keys into the secure input bar when prompted".to_string(),
        ]),
        Cloud::Gcp => AuthRequest::new(Cloud::Gcp, reason, vec![SecretKind::ServiceAccountJson])
            .with_guidance(
                "Prefer `gcloud auth login` (binary session / ADC). Or store a service-account JSON in the oscar keychain for this profile — never paste SA JSON into chat.",
            )
            .with_hints(vec![
                "oscar auth gcloud-login".to_string(),
                "oscar auth gcloud-login --adc".to_string(),
                format!("oscar auth gcp-sa --profile {pid} --file /path/to/sa.json"),
                "gcloud auth list && gcloud config set project <project-id>".to_string(),
            ]),
        Cloud::Azure => AuthRequest::new(
            Cloud::Azure,
            reason,
            vec![
                SecretKind::AzureTenantId,
                SecretKind::AzureClientId,
                SecretKind::AzureClientSecret,
            ],
        )
        .with_guidance(
            "Prefer `az login` (browser/device code) for a binary session. Service-principal secrets can be pasted into the TUI secure bar (tenant/client/secret) when prompted — never into chat text.",
        )
        .with_hints(vec![
            "oscar auth az-login".to_string(),
            "oscar auth az-login --tenant <tenant-id>".to_string(),
            "az account show && az account set --subscription <subscription-id>".to_string(),
            "TUI: secure bar for tenant id / client id / client secret when prompted".to_string(),
        ]),
        Cloud::K8s => AuthRequest::new(Cloud::K8s, reason, vec![SecretKind::Kubeconfig])
            .with_guidance(
                "Use a working kubectl context (kubeconfig). Oscar does not store cluster certs in chat.",
            )
            .with_hints(vec![
                "kubectl config get-contexts".to_string(),
                "kubectl config use-context <name>".to_string(),
                "kubectl cluster-info".to_string(),
            ]),
        Cloud::Multi => AuthRequest::new(Cloud::Multi, reason, vec![SecretKind::Other]),
    };
    if let Some(id) = profile_id {
        req = req.profile(id.to_string());
    }
    req
}

pub fn auth_for_profile(profile: &Profile, reason: impl Into<String>) -> AuthRequest {
    match profile.cloud {
        Cloud::Aws => auth_aws_needed(profile, false),
        other => auth_for_with_profile(other, Some(&profile.id), reason),
    }
}

/// Preferred auth method when scaffolding access for a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPrefer {
    /// CSP CLI SSO / browser login (binary session) — preferred default.
    BinarySso,
    /// Short-lived STS / session token in keychain.
    ShortLived,
    /// Long-lived keys in keychain (least preferred).
    LongLived,
}

impl AuthPrefer {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sso" | "binary" | "login" | "cli" | "browser" => Some(Self::BinarySso),
            "session" | "sts" | "short" | "short_lived" | "short-lived" => Some(Self::ShortLived),
            "keys" | "long" | "long_lived" | "long-lived" | "access_key" => Some(Self::LongLived),
            _ => None,
        }
    }
}

/// Build AuthRequest for a just-ensured profile, optionally reordering hints by preference.
pub fn auth_prepare_request(profile: &Profile, prefer: AuthPrefer) -> AuthRequest {
    let mut auth = auth_for_profile(
        profile,
        format!(
            "Sign in so oscar can use cloud `{}` via profile `{}` (account {})",
            profile.cloud, profile.id, profile.account_ref
        ),
    );
    // Put preferred path first in hints (agent + TUI show in order).
    let preferred: Vec<String> = match (profile.cloud, prefer) {
        (Cloud::Aws, AuthPrefer::BinarySso) => vec![
            format!("oscar auth aws-sso-login --profile {}", profile.id),
            "aws sso login".into(),
        ],
        (Cloud::Aws, AuthPrefer::ShortLived) => vec![
            format!(
                "oscar auth aws-session --profile {} --access-key-id … --secret-access-key … --session-token …",
                profile.id
            ),
            format!(
                "oscar auth aws-assume-role --profile {} --role-arn arn:aws:iam::…:role/…",
                profile.id
            ),
        ],
        (Cloud::Aws, AuthPrefer::LongLived) => vec![format!(
            "oscar auth aws-keys --profile {} --access-key-id … --secret-access-key …",
            profile.id
        )],
        (Cloud::Gcp, AuthPrefer::BinarySso) | (Cloud::Gcp, AuthPrefer::ShortLived) => {
            vec!["oscar auth gcloud-login".into(), "oscar auth gcloud-login --adc".into()]
        }
        (Cloud::Gcp, AuthPrefer::LongLived) => vec![format!(
            "oscar auth gcp-sa --profile {} --file /path/to/sa.json",
            profile.id
        )],
        (Cloud::Azure, _) => vec![
            "oscar auth az-login".into(),
            "TUI secure bar: tenant / client id / secret if using a service principal".into(),
        ],
        (Cloud::K8s, _) => vec![
            "kubectl config use-context <name>".into(),
            "kubectl cluster-info".into(),
        ],
        _ => vec![],
    };
    if !preferred.is_empty() {
        let mut rest = auth
            .hint_commands
            .iter()
            .filter(|h| !preferred.iter().any(|p| p == *h))
            .cloned()
            .collect::<Vec<_>>();
        let mut merged = preferred;
        merged.append(&mut rest);
        auth.hint_commands = merged;
    }
    auth
}

pub fn load_dns_cache(config_dir: &Path, profile_id: &str) -> Option<DnsInventory> {
    load_json(&dns_cache_path(config_dir, profile_id))
}

pub fn load_network_cache(
    config_dir: &Path,
    profile_id: &str,
    region: Option<&str>,
) -> Option<NetworkInventory> {
    load_json(&network_cache_path(config_dir, profile_id, region))
        .or_else(|| load_json(&network_cache_path(config_dir, profile_id, None)))
}

pub fn load_dns_resolver_cache(
    config_dir: &Path,
    profile_id: &str,
    region: Option<&str>,
) -> Option<crate::inventory::DnsResolverInventory> {
    use crate::inventory::dns_resolver_cache_path;
    load_json(&dns_resolver_cache_path(config_dir, profile_id, region)).or_else(|| {
        load_json(&dns_resolver_cache_path(config_dir, profile_id, None))
    })
}
