use crate::sync_network::AwsNetworkSource;
use async_trait::async_trait;
use oscar_core::{Capability, Cloud, PatternQuery, ToolDomain};
use oscar_tools::sync::NetworkInventorySource;
use oscar_tools::{
    auth_for, discovery_blurb, discovery_tool_result, ensure_network_inventory, load_network_cache,
    pattern_properties, resolve_profiles, scan_network_inventory, to_tool_result,
    write_network_cache, Tool, ToolContext, ToolMeta, ToolResult,
};
use serde_json::json;

pub use crate::path_live::{AwsNetworkAccessAnalyze, AwsNetworkPathAnalyze};
pub struct AwsNetworkPatternSearch;
pub struct AwsNetworkSubnetPattern;
pub struct AwsNetworkVpcPattern;
pub struct AwsNetworkIpLocate;
pub struct AwsNetworkInventorySync;

async fn run_network_pattern(
    args: serde_json::Value,
    ctx: &ToolContext,
    kinds_filter: Option<&[&str]>,
    scope_label: &str,
) -> ToolResult {
    let q = match PatternQuery::from_args(&args) {
        Ok(q) => q,
        Err(e) => return ToolResult::error(e),
    };
    let profiles = ctx.profiles_for(Cloud::Aws, q.profile_id.as_deref());
    if profiles.is_empty() {
        return ToolResult::needs_auth(auth_for(
            Cloud::Aws,
            format!("AWS profile required for network pattern search `{}`", q.pattern),
        ));
    }

    let force = args
        .get("refresh")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut merged = oscar_core::DiscoveryResult::empty(
        &q.pattern,
        q.mode,
        format!("aws.{scope_label}:{} profiles", profiles.len()),
    );
    let source = AwsNetworkSource;
    let mut any = false;
    for p in profiles {
        let inv = match ensure_network_inventory(
            &ctx.config_dir,
            p,
            &source,
            q.region.as_deref(),
            force,
        )
        .await
        {
            Ok(inv) => {
                any = true;
                inv
            }
            Err(e) => {
                merged.partial = true;
                merged.notes.push(format!("profile `{}`: {e}", p.id));
                if let Some(cached) = load_network_cache(&ctx.config_dir, &p.id, q.region.as_deref())
                {
                    any = true;
                    cached
                } else {
                    continue;
                }
            }
        };
        let mut part = scan_network_inventory(&inv, &q);
        if let Some(filters) = kinds_filter {
            part.hits.retain(|h| {
                let k = h.kind.to_string();
                filters.iter().any(|f| k == *f)
            });
        }
        merged.hits.append(&mut part.hits);
    }
    if !any {
        merged.partial = true;
        merged.notes.push(
            "No AWS network inventory. Run aws.network.inventory.sync or: oscar inventory sync --cloud aws --kind network (or seed-fixture).".into(),
        );
    }
    merged.hits.truncate(q.limit);
    to_tool_result(discovery_tool_result(merged.finalize()))
}

#[async_trait]
impl Tool for AwsNetworkInventorySync {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.network.inventory.sync".into(),
            name: "Sync VPC/subnet/IP into unified NetworkInventory".into(),
            description: "Live-fetch AWS VPCs, subnets, ENI/EIP addresses via aws ec2 describe-*, map to unified NetworkInventory, write cache for pattern search.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "sync".into(),
                "inventory".into(),
                "vpc".into(),
                "subnet".into(),
                "cache".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" },
                    "region": { "type": "string" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profiles = ctx.profiles_for(Cloud::Aws, args.get("profile_id").and_then(|v| v.as_str()),
        );
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(
                Cloud::Aws,
                "AWS profile required to sync network inventory",
            ));
        }
        let region = args.get("region").and_then(|v| v.as_str());
        let source = AwsNetworkSource;
        let mut details = Vec::new();
        let mut vpcs = 0usize;
        let mut subnets = 0usize;
        let mut addrs = 0usize;
        for p in profiles {
            let r = region.or(p.default_region.as_deref());
            match source.sync_network(p, r).await {
                Ok(inv) => {
                    vpcs += inv.vpcs.len();
                    subnets += inv.subnets.len();
                    addrs += inv.addresses.len();
                    let _ = write_network_cache(&ctx.config_dir, &inv);
                    details.push(format!(
                        "{}: vpcs={} subnets={} addresses={} (NetworkInventory)",
                        p.id,
                        inv.vpcs.len(),
                        inv.subnets.len(),
                        inv.addresses.len()
                    ));
                }
                Err(e) => details.push(format!("{}: ERROR {e}", p.id)),
            }
        }
        ToolResult::success(
            format!("AWS network sync: {vpcs} vpcs, {subnets} subnets, {addrs} addresses"),
            json!({
                "cloud": "aws",
                "format": "NetworkInventory",
                "vpcs": vpcs,
                "subnets": subnets,
                "addresses": addrs,
                "details": details
            }),
        )
    }
}

#[async_trait]
impl Tool for AwsNetworkPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.network.pattern.search".into(),
            name: "Pattern search VPCs, subnets, IPs".into(),
            description: discovery_blurb(
                "AWS VPCs, subnet CIDRs/names, and addresses — partial IP (10.0.4), CIDR containment, or name glob",
            ),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "pattern".into(),
                "search".into(),
                "discover".into(),
                "partial".into(),
                "subnet".into(),
                "vpc".into(),
                "ip".into(),
                "cidr".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": pattern_properties(),
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, None, "network.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkSubnetPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.network.subnet.pattern".into(),
            name: "Pattern search subnets only".into(),
            description: discovery_blurb(
                "AWS subnets only — partial CIDR/name match (e.g. 10.0.4, app-*, subnet-abc)",
            ),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "subnet".into(),
                "pattern".into(),
                "search".into(),
                "cidr".into(),
                "partial".into(),
                "network".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": pattern_properties(),
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["subnet"]), "subnet.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkVpcPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.network.vpc.pattern".into(),
            name: "Pattern search VPCs only".into(),
            description: discovery_blurb("AWS VPCs by id, name, or CIDR fragment"),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "vpc".into(),
                "pattern".into(),
                "search".into(),
                "cidr".into(),
                "network".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": pattern_properties(),
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["vpc"]), "vpc.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkIpLocate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.network.ip.locate".into(),
            name: "Locate IP / IP fragment in AWS".into(),
            description: "Find which VPC/subnet/ENI-like address inventory contains an IP or partial IP (e.g. 10.0.4.12 or 10.0.4). Faster than Reachability Analyzer for ownership discovery.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "ip".into(),
                "locate".into(),
                "pattern".into(),
                "subnet".into(),
                "vpc".into(),
                "discover".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "IP, fragment, or CIDR" },
                    "ip": { "type": "string", "description": "Alias for pattern" },
                    "profile_id": { "type": "string" },
                    "region": { "type": "string" },
                    "limit": { "type": "integer", "default": 50 }
                },
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, mut args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Some(obj) = args.as_object_mut() {
            if !obj.contains_key("pattern") {
                if let Some(ip) = obj.get("ip").cloned() {
                    obj.insert("pattern".into(), ip);
                }
            }
            obj.insert("mode".into(), json!("ip_or_cidr"));
        }
        run_network_pattern(args, ctx, None, "ip.locate").await
    }
}
