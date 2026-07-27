//! GCP DNS policy / response policy / forwarding tools.

use crate::sync_resolver::{DnsResolverInventorySource, GcpDnsResolverSource};
use async_trait::async_trait;
use oscar_core::{Capability, Cloud, PatternQuery, ToolDomain};
use oscar_tools::{
    auth_for, discovery_blurb, discovery_tool_result, load_dns_resolver_cache, pattern_properties,
    resolve_profiles, scan_dns_resolver_inventory, to_tool_result, write_dns_resolver_cache, Tool,
    ToolContext, ToolMeta, ToolResult,
};
use serde_json::json;

pub struct GcpDnsResolverInventorySync;
pub struct GcpDnsPolicyPatternSearch;

#[async_trait]
impl Tool for GcpDnsResolverInventorySync {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.dns.resolver.inventory.sync".into(),
            name: "Sync GCP DNS policies & forwarding zones".into(),
            description: "Live-fetch Cloud DNS policies, response policies, and forwarding/peering zones via gcloud into unified DnsResolverInventory.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Gcp],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "policy".into(),
                "forwarding".into(),
                "peering".into(),
                "response-policy".into(),
                "sync".into(),
                "inventory".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profiles = resolve_profiles(
            &ctx.profiles,
            Cloud::Gcp,
            args.get("profile_id").and_then(|v| v.as_str()),
        );
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(
                Cloud::Gcp,
                "GCP profile required to sync DNS policies",
            ));
        }
        let source = GcpDnsResolverSource;
        let mut details = Vec::new();
        let mut policies = 0usize;
        for p in profiles {
            match source.sync_resolver(p, None).await {
                Ok(inv) => {
                    policies += inv.policies.len();
                    let _ = write_dns_resolver_cache(&ctx.config_dir, &inv);
                    details.push(format!("{}: {} policies/zones", p.id, inv.policies.len()));
                }
                Err(e) => details.push(format!("{}: ERROR {e}", p.id)),
            }
        }
        ToolResult::success(
            format!("GCP DNS policy sync: {policies} policies/forwarding/peering entries"),
            json!({
                "cloud": "gcp",
                "format": "DnsResolverInventory",
                "policies": policies,
                "details": details
            }),
        )
    }
}

#[async_trait]
impl Tool for GcpDnsPolicyPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.dns.policy.pattern.search".into(),
            name: "Pattern search GCP DNS policies & forwarding".into(),
            description: discovery_blurb(
                "GCP Cloud DNS policies, response policies, forwarding zones, and peering zones",
            ),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Gcp],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "policy".into(),
                "forwarding".into(),
                "peering".into(),
                "pattern".into(),
                "search".into(),
                "response-policy".into(),
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
        let q = match PatternQuery::from_args(&args) {
            Ok(q) => q,
            Err(e) => return ToolResult::error(e),
        };
        let profiles = resolve_profiles(&ctx.profiles, Cloud::Gcp, q.profile_id.as_deref());
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(Cloud::Gcp, "GCP profile required"));
        }
        let force = args
            .get("refresh")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mut merged = oscar_core::DiscoveryResult::empty(
            &q.pattern,
            q.mode,
            format!("gcp.dns.policy:{} profiles", profiles.len()),
        );
        let source = GcpDnsResolverSource;
        for p in profiles {
            let inv = if force {
                match source.sync_resolver(p, None).await {
                    Ok(inv) => {
                        let _ = write_dns_resolver_cache(&ctx.config_dir, &inv);
                        inv
                    }
                    Err(e) => {
                        merged.partial = true;
                        merged.notes.push(format!("{}: {e}", p.id));
                        if let Some(c) = load_dns_resolver_cache(&ctx.config_dir, &p.id, None) {
                            c
                        } else {
                            continue;
                        }
                    }
                }
            } else if let Some(c) = load_dns_resolver_cache(&ctx.config_dir, &p.id, None) {
                c
            } else {
                match source.sync_resolver(p, None).await {
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
            part.hits.retain(|h| {
                matches!(
                    h.kind.to_string().as_str(),
                    "dns_policy" | "dns_resolver_rule" | "dns_resolver_endpoint"
                )
            });
            merged.hits.append(&mut part.hits);
        }
        merged.hits.truncate(q.limit);
        to_tool_result(discovery_tool_result(merged.finalize()))
    }
}
