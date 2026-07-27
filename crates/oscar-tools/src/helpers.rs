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
    let reason = reason.into();
    match cloud {
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
            "Use short-lived STS/SSO session tokens when possible, or long-lived keys in oscar keychain. Default env AWS_* is not read for oscar tools. Detected `aws` binary sessions are allowed.",
        )
        .with_hints([
            "aws sso login",
            "oscar auth aws-session --profile <id> …",
            "oscar auth aws-keys --profile <id> …",
            "oscar auth aws-assume-role --profile <id> --role-arn arn:…",
        ]),
        Cloud::Gcp => AuthRequest::new(Cloud::Gcp, reason, vec![SecretKind::ServiceAccountJson])
            .with_guidance("Prefer gcloud ADC/user login (binary session) or store SA JSON in keychain.")
            .with_hints(["gcloud auth login", "oscar auth gcp-sa --profile <id> --file sa.json"]),
        Cloud::Azure => AuthRequest::new(
            Cloud::Azure,
            reason,
            vec![
                SecretKind::AzureTenantId,
                SecretKind::AzureClientId,
                SecretKind::AzureClientSecret,
            ],
        )
        .with_hints(["az login", "oscar auth azure-sp --profile <id> …"]),
        Cloud::K8s => AuthRequest::new(Cloud::K8s, reason, vec![SecretKind::Kubeconfig])
            .with_hints(["kubectl config current-context"]),
        Cloud::Multi => AuthRequest::new(Cloud::Multi, reason, vec![SecretKind::Other]),
    }
}

pub fn auth_for_profile(profile: &Profile, reason: impl Into<String>) -> AuthRequest {
    match profile.cloud {
        Cloud::Aws => auth_aws_needed(profile, false),
        other => auth_for(other, reason).profile(profile.id.clone()),
    }
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
