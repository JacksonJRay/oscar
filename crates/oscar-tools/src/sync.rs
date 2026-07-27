//! Live inventory sync: CSP-native fetch → **unified** inventory DTOs → cache.
//!
//! All pattern-search tools consume only unified shapes (`DnsInventory`,
//! `NetworkInventory`, `K8sInventory`). Per-CSP adapters implement
//! [`DnsInventorySource`] / etc. and never leak raw API JSON to the agent.

use crate::inventory::{
    dns_cache_path, k8s_cache_path, network_cache_path, save_json, DnsInventory, K8sInventory,
    NetworkInventory,
};
use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_identity::Profile;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, warn};

/// Sync DNS for one profile into the unified inventory format.
#[async_trait]
pub trait DnsInventorySource: Send + Sync {
    fn cloud(&self) -> Cloud;
    async fn sync_dns(&self, profile: &Profile, opts: &DnsSyncOpts) -> OscarResult<DnsInventory>;
}

#[derive(Debug, Clone)]
pub struct DnsSyncOpts {
    /// When true, fetch record sets for each zone (slower, needed for pattern search depth).
    pub include_records: bool,
    /// Cap zones when listing records (0 = no cap).
    pub max_zones_for_records: usize,
    /// Cap records per zone (0 = no cap).
    pub max_records_per_zone: usize,
}

impl Default for DnsSyncOpts {
    fn default() -> Self {
        Self {
            include_records: true,
            max_zones_for_records: 200,
            max_records_per_zone: 5_000,
        }
    }
}

#[async_trait]
pub trait NetworkInventorySource: Send + Sync {
    fn cloud(&self) -> Cloud;
    async fn sync_network(
        &self,
        profile: &Profile,
        region: Option<&str>,
    ) -> OscarResult<NetworkInventory>;
}

#[async_trait]
pub trait K8sInventorySource: Send + Sync {
    async fn sync_k8s(&self, context: Option<&str>) -> OscarResult<K8sInventory>;
}

/// Persist unified DNS inventory to the standard cache path.
pub fn write_dns_cache(config_dir: &Path, inv: &DnsInventory) -> OscarResult<()> {
    let path = dns_cache_path(config_dir, &inv.profile_id);
    save_json(&path, inv).map_err(OscarError::from)?;
    debug!(path = %path.display(), zones = inv.zones.len(), "wrote DNS inventory cache");
    Ok(())
}

pub fn write_network_cache(config_dir: &Path, inv: &NetworkInventory) -> OscarResult<()> {
    let path = network_cache_path(config_dir, &inv.profile_id, inv.region.as_deref());
    save_json(&path, inv).map_err(OscarError::from)?;
    Ok(())
}

pub fn write_k8s_cache(config_dir: &Path, key: &str, inv: &K8sInventory) -> OscarResult<()> {
    let path = k8s_cache_path(config_dir, key);
    save_json(&path, inv).map_err(OscarError::from)?;
    Ok(())
}

pub fn write_dns_resolver_cache(
    config_dir: &Path,
    inv: &crate::inventory::DnsResolverInventory,
) -> OscarResult<()> {
    let path = crate::inventory::dns_resolver_cache_path(
        config_dir,
        &inv.profile_id,
        inv.region.as_deref(),
    );
    save_json(&path, inv).map_err(OscarError::from)?;
    Ok(())
}

/// Run a CLI and parse stdout as JSON.
pub async fn run_json_command(program: &str, args: &[&str]) -> OscarResult<serde_json::Value> {
    run_json_command_with_env(program, args, &[]).await
}

/// Run a CLI with extra environment (e.g. short-lived AWS keys from keychain).
pub async fn run_json_command_with_env(
    program: &str,
    args: &[&str],
    env: &[(String, String)],
) -> OscarResult<serde_json::Value> {
    debug!(program, ?args, env_keys = env.len(), "inventory sync command");
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    // When keychain/session env provides AWS keys, avoid accidental profile override noise.
    if env.iter().any(|(k, _)| k == "AWS_ACCESS_KEY_ID") {
        cmd.env_remove("AWS_PROFILE");
        cmd.env_remove("AWS_DEFAULT_PROFILE");
    }

    let output = cmd.output().await.map_err(|e| {
        OscarError::Tool(format!(
            "failed to spawn `{program}`: {e}. Is the CLI installed and on PATH?"
        ))
    })?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let out = String::from_utf8_lossy(&output.stdout);
        return Err(OscarError::Tool(format!(
            "`{program} {}` failed ({}): {} {}",
            args.join(" "),
            output.status,
            err.trim(),
            out.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_str(stdout.trim()).map_err(|e| {
        OscarError::Tool(format!(
            "failed to parse JSON from `{program}`: {e}; head={}",
            stdout.chars().take(200).collect::<String>()
        ))
    })
}

pub async fn which_ok(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// AWS profile flag / env for CLI (uses oscar profile label or account as AWS_PROFILE hint).
pub fn aws_cli_profile_args(profile: &Profile) -> Vec<String> {
    // Prefer explicit region on profile; AWS profile name often matches label.
    let mut args = Vec::new();
    if !profile.label.is_empty() && profile.label != "default" {
        // Only pass --profile if it looks like an AWS named profile (no spaces).
        if !profile.label.contains(' ') {
            args.push("--profile".into());
            args.push(profile.label.clone());
        }
    }
    if let Some(r) = &profile.default_region {
        // Route 53 is global; region flag rarely needed but harmless for other calls.
        let _ = r;
    }
    args
}

pub fn gcloud_project_args(profile: &Profile) -> Vec<String> {
    vec!["--project".into(), profile.account_ref.clone()]
}

/// Load DNS inventory: cache first; if missing/stale and source provided, live sync.
pub async fn ensure_dns_inventory(
    config_dir: &Path,
    profile: &Profile,
    source: &dyn DnsInventorySource,
    opts: &DnsSyncOpts,
    force: bool,
) -> OscarResult<DnsInventory> {
    if !force {
        if let Some(inv) = crate::inventory::load_json(&dns_cache_path(config_dir, &profile.id)) {
            return Ok(inv);
        }
    }
    let inv = source.sync_dns(profile, opts).await?;
    if let Err(e) = write_dns_cache(config_dir, &inv) {
        warn!("failed to write DNS cache: {e}");
    }
    Ok(inv)
}

/// Load network inventory: cache first; live sync on miss when `force` or empty.
pub async fn ensure_network_inventory(
    config_dir: &Path,
    profile: &Profile,
    source: &dyn NetworkInventorySource,
    region: Option<&str>,
    force: bool,
) -> OscarResult<NetworkInventory> {
    if !force {
        if let Some(inv) =
            crate::inventory::load_json(&network_cache_path(config_dir, &profile.id, region))
                .or_else(|| {
                    crate::inventory::load_json(&network_cache_path(config_dir, &profile.id, None))
                })
        {
            return Ok(inv);
        }
    }
    let inv = source.sync_network(profile, region).await?;
    if let Err(e) = write_network_cache(config_dir, &inv) {
        warn!("failed to write network cache: {e}");
    }
    Ok(inv)
}
