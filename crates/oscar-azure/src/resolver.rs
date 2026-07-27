//! Azure Private DNS links + Private Resolver tools.

use crate::sync_resolver::{AzureDnsResolverSource, DnsResolverInventorySource};
use async_trait::async_trait;
use oscar_core::{Capability, Cloud, PatternQuery, ToolDomain};
use oscar_tools::{
    auth_for, discovery_blurb, discovery_tool_result, load_dns_resolver_cache, pattern_properties,
    resolve_profiles, scan_dns_resolver_inventory, to_tool_result, write_dns_resolver_cache, Tool,
    ToolContext, ToolMeta, ToolResult,
};
use serde_json::json;

pub struct AzureDnsResolverInventorySync;
pub struct AzureDnsVnetLinkPatternSearch;
pub struct AzureDnsPrivateResolverPatternSearch;

#[async_trait]
impl Tool for AzureDnsResolverInventorySync {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.dns.resolver.inventory.sync".into(),
            name: "Sync Azure Private DNS links & Private Resolver".into(),
            description: "Live-fetch Private DNS virtual network links and DNS Private Resolvers (inbound/outbound/rulesets) via az into unified DnsResolverInventory.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "private-dns".into(),
                "vnet-link".into(),
                "private-resolver".into(),
                "sync".into(),
                "inventory".into(),
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
        let profiles = ctx.profiles_for(Cloud::Azure, args.get("profile_id").and_then(|v| v.as_str()),
        );
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(
                Cloud::Azure,
                "Azure profile required to sync Private DNS resolver inventory",
            ));
        }
        let region = args.get("region").and_then(|v| v.as_str());
        let source = AzureDnsResolverSource;
        let mut details = Vec::new();
        let mut links = 0usize;
        let mut resolvers = 0usize;
        for p in profiles {
            let r = region.or(p.default_region.as_deref());
            match source.sync_resolver(p, r).await {
                Ok(inv) => {
                    links += inv.vnet_links.len();
                    resolvers += inv.private_resolvers.len();
                    let _ = write_dns_resolver_cache(&ctx.config_dir, &inv);
                    details.push(format!(
                        "{}: vnet_links={} private_resolvers={}",
                        p.id,
                        inv.vnet_links.len(),
                        inv.private_resolvers.len()
                    ));
                }
                Err(e) => details.push(format!("{}: ERROR {e}", p.id)),
            }
        }
        ToolResult::success(
            format!("Azure DNS resolver sync: {links} vnet links, {resolvers} private resolvers"),
            json!({
                "cloud": "azure",
                "format": "DnsResolverInventory",
                "vnet_links": links,
                "private_resolvers": resolvers,
                "details": details
            }),
        )
    }
}

async fn azure_resolver_pattern(
    args: serde_json::Value,
    ctx: &ToolContext,
    kind_filter: Option<&str>,
) -> ToolResult {
    let q = match PatternQuery::from_args(&args) {
        Ok(q) => q,
        Err(e) => return ToolResult::error(e),
    };
    let profiles = ctx.profiles_for(Cloud::Azure, q.profile_id.as_deref());
    if profiles.is_empty() {
        return ToolResult::needs_auth(auth_for(Cloud::Azure, "Azure profile required"));
    }
    let force = args
        .get("refresh")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut merged = oscar_core::DiscoveryResult::empty(
        &q.pattern,
        q.mode,
        format!("azure.dns.resolver:{} profiles", profiles.len()),
    );
    let source = AzureDnsResolverSource;
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
                    merged.notes.push(format!("{}: {e}", p.id));
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
                    merged.notes.push(format!("{}: {e}", p.id));
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
impl Tool for AzureDnsVnetLinkPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.dns.vnet_link.pattern.search".into(),
            name: "Pattern search Azure Private DNS VNet links".into(),
            description: discovery_blurb(
                "Azure Private DNS virtual network links (zone ↔ VNet associations)",
            ),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "private-dns".into(),
                "vnet-link".into(),
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
        azure_resolver_pattern(args, ctx, Some("dns_vnet_link")).await
    }
}

#[async_trait]
impl Tool for AzureDnsPrivateResolverPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.dns.private_resolver.pattern.search".into(),
            name: "Pattern search Azure DNS Private Resolver".into(),
            description: discovery_blurb(
                "Azure DNS Private Resolver instances, inbound/outbound endpoints, and forwarding rulesets",
            ),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "private-resolver".into(),
                "forwarding".into(),
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
        azure_resolver_pattern(args, ctx, Some("dns_private_resolver")).await
    }
}
