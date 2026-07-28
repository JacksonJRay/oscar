//! Route 53 Resolver / DNS Firewall tools.

use crate::sync_resolver::{AwsDnsResolverSource, DnsResolverInventorySource};
use async_trait::async_trait;
use oscar_core::{Capability, Cloud, PatternQuery, ToolDomain};
use oscar_tools::{
    auth_for, discovery_blurb, discovery_tool_result, load_dns_resolver_cache, pattern_properties,
    resolve_profiles, scan_dns_resolver_inventory, to_tool_result, write_dns_resolver_cache, Tool,
    ToolContext, ToolMeta, ToolResult,
};
use serde_json::json;

pub struct AwsDnsResolverInventorySync;
pub struct AwsDnsResolverPatternSearch;
pub struct AwsDnsFirewallPatternSearch;
pub struct AwsDnsQueryLogPatternSearch;
pub struct AwsDnsProfilePatternSearch;

fn needs_aws(ctx: &ToolContext, reason: &str) -> Option<ToolResult> {
    if ctx.profiles.list().iter().any(|p| p.cloud == Cloud::Aws) {
        None
    } else {
        Some(ToolResult::needs_auth(auth_for(Cloud::Aws, reason)))
    }
}

#[async_trait]
impl Tool for AwsDnsResolverInventorySync {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.dns.resolver.inventory.sync".into(),
            name: "Sync Route 53 Resolver inventory".into(),
            description: "Live-fetch Route 53 Resolver inbound/outbound endpoints, forwarding rules, DNS Firewall rule groups, and query log configs via aws route53resolver; map to unified DnsResolverInventory cache.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "resolver".into(),
                "route53".into(),
                "sync".into(),
                "inventory".into(),
                "firewall".into(),
                "query-log".into(),
                "forward".into(),
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
        if let Some(r) = needs_aws(ctx, "AWS profile required to sync Route 53 Resolver") {
            return r;
        }
        let profiles = ctx.profiles_for(Cloud::Aws, args.get("profile_id").and_then(|v| v.as_str()),
        );
        let region = args.get("region").and_then(|v| v.as_str());
        let source = AwsDnsResolverSource;
        let mut details = Vec::new();
        let mut endpoints = 0usize;
        let mut rules = 0usize;
        let mut firewall = 0usize;
        let mut qlogs = 0usize;
        for p in profiles {
            let r = region.or(p.default_region.as_deref());
            match source.sync_resolver(p, r).await {
                Ok(inv) => {
                    endpoints += inv.endpoints.len();
                    rules += inv.rules.len();
                    firewall += inv.firewall_rule_groups.len();
                    qlogs += inv.query_log_configs.len();
                    let _ = write_dns_resolver_cache(&ctx.config_dir, &inv);
                    details.push(format!(
                        "{}: endpoints={} rules={} firewall_groups={} query_logs={}",
                        p.id,
                        inv.endpoints.len(),
                        inv.rules.len(),
                        inv.firewall_rule_groups.len(),
                        inv.query_log_configs.len()
                    ));
                }
                Err(e) => details.push(format!("{}: ERROR {e}", p.id)),
            }
        }
        ToolResult::success(
            format!(
                "AWS Resolver sync: {endpoints} endpoints, {rules} rules, {firewall} firewall groups, {qlogs} query logs"
            ),
            json!({
                "cloud": "aws",
                "format": "DnsResolverInventory",
                "endpoints": endpoints,
                "rules": rules,
                "firewall_rule_groups": firewall,
                "query_log_configs": qlogs,
                "details": details
            }),
        )
    }
}

async fn resolver_pattern(
    args: serde_json::Value,
    ctx: &ToolContext,
    kind_filter: Option<&str>,
) -> ToolResult {
    let q = match PatternQuery::from_args(&args) {
        Ok(q) => q,
        Err(e) => return ToolResult::error(e),
    };
    let profiles = ctx.profiles_for(Cloud::Aws, q.profile_id.as_deref());
    if profiles.is_empty() {
        return ToolResult::needs_auth(auth_for(
            Cloud::Aws,
            format!("AWS profile required for resolver search `{}`", q.pattern),
        ));
    }
    let force = args
        .get("refresh")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut merged = oscar_core::DiscoveryResult::empty(
        &q.pattern,
        q.mode,
        format!("aws.dns.resolver:{} profiles", profiles.len()),
    );
    let source = AwsDnsResolverSource;
    for p in profiles {
        let region = q.region.as_deref().or(p.default_region.as_deref());
        let inv = if force {
            match source.sync_resolver(p, region).await {
                Ok(inv) => {
                    let _ = write_dns_resolver_cache(&ctx.config_dir, &inv);
                    inv
                }
                Err(e) => {
                    merged.partial = true;
                    merged.notes.push(format!("profile `{}`: {e}", p.id));
                    if let Some(c) = load_dns_resolver_cache(&ctx.config_dir, &p.id, region) {
                        c
                    } else {
                        continue;
                    }
                }
            }
        } else if let Some(c) = load_dns_resolver_cache(&ctx.config_dir, &p.id, region) {
            c
        } else {
            match source.sync_resolver(p, region).await {
                Ok(inv) => {
                    let _ = write_dns_resolver_cache(&ctx.config_dir, &inv);
                    inv
                }
                Err(e) => {
                    merged.partial = true;
                    merged.notes.push(format!("profile `{}`: {e}", p.id));
                    continue;
                }
            }
        };
        let mut part = scan_dns_resolver_inventory(&inv, &q);
        if let Some(kf) = kind_filter {
            part.hits.retain(|h| h.kind.to_string() == kf);
        }
        merged.hits.append(&mut part.hits);
    }
    merged.hits.truncate(q.limit);
    to_tool_result(discovery_tool_result(merged.finalize()))
}

#[async_trait]
impl Tool for AwsDnsResolverPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.dns.resolver.pattern.search".into(),
            name: "Pattern search Route 53 Resolver endpoints & rules".into(),
            description: discovery_blurb(
                "AWS Route 53 Resolver inbound/outbound endpoints and forwarding rules (domain, target IP, VPC)",
            ),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "resolver".into(),
                "route53".into(),
                "pattern".into(),
                "search".into(),
                "forward".into(),
                "inbound".into(),
                "outbound".into(),
                "partial".into(),
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
        // Include both endpoints and rules (no kind filter)
        resolver_pattern(args, ctx, None).await
    }
}

#[async_trait]
impl Tool for AwsDnsFirewallPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.dns.firewall.pattern.search".into(),
            name: "Pattern search Route 53 DNS Firewall rule groups".into(),
            description: discovery_blurb(
                "AWS Route 53 Resolver DNS Firewall rule groups (egress domain control)",
            ),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "firewall".into(),
                "route53".into(),
                "pattern".into(),
                "search".into(),
                "resolver".into(),
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
        resolver_pattern(args, ctx, Some("dns_firewall_rule_group")).await
    }
}

#[async_trait]
impl Tool for AwsDnsQueryLogPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.dns.querylog.pattern.search".into(),
            name: "Pattern search Resolver query log configs".into(),
            description: discovery_blurb(
                "AWS Route 53 Resolver query logging configurations (destination ARN / name)",
            ),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "query-log".into(),
                "logging".into(),
                "route53".into(),
                "pattern".into(),
                "search".into(),
                "resolver".into(),
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
        resolver_pattern(args, ctx, Some("dns_query_log_config")).await
    }
}

#[async_trait]
impl Tool for AwsDnsProfilePatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.dns.profile.pattern.search".into(),
            name: "Pattern search Route 53 Profiles".into(),
            description: discovery_blurb(
                "AWS Route 53 Profiles (multi-account PHZ / firewall / query-logging share)",
            ),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "profile".into(),
                "route53".into(),
                "share".into(),
                "pattern".into(),
                "search".into(),
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
        resolver_pattern(args, ctx, Some("dns_profile")).await
    }
}
