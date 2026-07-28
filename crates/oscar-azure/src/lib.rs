//! Azure tools: DNS + network inventory + Network Watcher + pattern discovery.

mod iam;
mod network_write;
mod resolver;
mod sync_dns;
mod sync_network;
mod sync_resolver;

pub use sync_dns::AzureDnsSource;
pub use sync_network::AzureNetworkSource;
pub use sync_resolver::{
    AzureDnsResolverSource, DnsResolverInventorySource as AzureDnsResolverInventorySource,
};

use async_trait::async_trait;
use oscar_core::{Capability, Cloud, PatternQuery, ToolDomain};
use oscar_tools::sync::{ensure_dns_inventory, DnsInventorySource, NetworkInventorySource};
use oscar_tools::{
    auth_for, discovery_blurb, discovery_tool_result, ensure_network_inventory, load_dns_cache,
    load_network_cache, pattern_properties, resolve_profiles, scan_dns_inventory,
    scan_network_inventory, to_tool_result, write_dns_cache, write_network_cache, DnsSyncOpts,
    Tool, ToolContext, ToolMeta, ToolRegistry, ToolResult,
};
use serde_json::json;
use std::sync::Arc;

pub fn register(registry: &mut ToolRegistry) {
    registry.register(Arc::new(AzureDnsZonesList));
    registry.register(Arc::new(AzureDnsRecordLookup));
    registry.register(Arc::new(AzureDnsPatternSearch));
    registry.register(Arc::new(AzureDnsInventorySync));
    registry.register(Arc::new(AzureDnsRecordCreate));
    registry.register(Arc::new(AzureDnsRecordDelete));
    registry.register(Arc::new(AzureNetworkPathTroubleshoot));
    registry.register(Arc::new(AzureNetworkNextHop));
    registry.register(Arc::new(AzureNetworkPatternSearch));
    registry.register(Arc::new(AzureNetworkSubnetPattern));
    registry.register(Arc::new(AzureNetworkVnetPattern));
    registry.register(Arc::new(AzureNetworkNsgPattern));
    registry.register(Arc::new(AzureNetworkRouteTablePattern));
    registry.register(Arc::new(AzureNetworkRoutePattern));
    registry.register(Arc::new(AzureComputeFunctionPattern));
    registry.register(Arc::new(AzureNetworkPeeringPattern));
    registry.register(Arc::new(AzureNetworkVpnPattern));
    registry.register(Arc::new(AzureNetworkHybridPattern));
    registry.register(Arc::new(AzureNetworkEndpointPattern));
    registry.register(Arc::new(AzureNetworkNatPattern));
    registry.register(Arc::new(AzureNetworkServicePattern));
    registry.register(Arc::new(AzureNetworkIpLocate));
    registry.register(Arc::new(AzureNetworkInventorySync));
    // Network write (create/delete) — Capability::Write, mode-gated
    network_write::register_network_write(registry);
    // Track C — Private DNS VNet links + Private Resolver
    registry.register(Arc::new(resolver::AzureDnsResolverInventorySync));
    registry.register(Arc::new(resolver::AzureDnsVnetLinkPatternSearch));
    registry.register(Arc::new(resolver::AzureDnsPrivateResolverPatternSearch));
    iam::register_iam(registry);
}

struct AzureNetworkInventorySync;

struct AzureDnsInventorySync;

struct AzureDnsZonesList;
struct AzureDnsRecordLookup;
struct AzureDnsPatternSearch;
struct AzureDnsRecordCreate;
struct AzureDnsRecordDelete;
// AzureDnsInventorySync defined above
struct AzureNetworkPathTroubleshoot;
struct AzureNetworkNextHop;
struct AzureNetworkPatternSearch;
struct AzureNetworkSubnetPattern;
struct AzureNetworkVnetPattern;
struct AzureNetworkNsgPattern;
struct AzureNetworkRouteTablePattern;
struct AzureNetworkRoutePattern;
struct AzureComputeFunctionPattern;
struct AzureNetworkPeeringPattern;
struct AzureNetworkVpnPattern;
struct AzureNetworkHybridPattern;
struct AzureNetworkEndpointPattern;
struct AzureNetworkNatPattern;
struct AzureNetworkServicePattern;
struct AzureNetworkIpLocate;

#[async_trait]
impl Tool for AzureDnsZonesList {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.dns.zones.list".into(),
            name: "List Azure DNS zones".into(),
            description: "List Azure DNS and Private DNS zones. Prefer azure.dns.pattern.search for fragments.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec!["dns".into(), "zones".into(), "list".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" },
                    "resource_group": { "type": "string" }
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
                "Azure credentials required to list DNS zones",
            ));
        }
        let mut zones = Vec::new();
        let mut partial = false;
        for p in profiles {
            if let Some(inv) = load_dns_cache(&ctx.config_dir, &p.id) {
                for z in inv.zones {
                    zones.push(json!({"profile_id": p.id, "id": z.id, "name": z.name, "private": z.private}));
                }
            } else {
                partial = true;
            }
        }
        ToolResult::success(
            format!("{} zone(s) from cache", zones.len()),
            json!({ "zones": zones, "partial": partial }),
        )
    }
}

#[async_trait]
impl Tool for AzureDnsRecordLookup {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.dns.record.lookup".into(),
            name: "Lookup Azure DNS record (partial)".into(),
            description: "Find Azure DNS records by name fragment (partial match by default). Delegates to azure.dns.pattern.search.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "record".into(),
                "lookup".into(),
                "partial".into(),
                "search".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Record name or partial fragment" },
                    "type": { "type": "string" },
                    "profile_id": { "type": "string" }
                },
                "required": ["name"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            return ToolResult::error("name is required");
        }
        let mut a = args.clone();
        if let Some(obj) = a.as_object_mut() {
            obj.insert("pattern".into(), json!(name));
            obj.insert("mode".into(), json!("partial"));
        }
        AzureDnsPatternSearch.execute(a, ctx).await
    }
}

#[async_trait]
impl Tool for AzureDnsPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.dns.pattern.search".into(),
            name: "Pattern search Azure DNS zones & records".into(),
            description: discovery_blurb("Azure DNS and Private DNS zones/records"),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "pattern".into(),
                "search".into(),
                "discover".into(),
                "partial".into(),
                "glob".into(),
                "private".into(),
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
        let profiles = ctx.profiles_for(Cloud::Azure, q.profile_id.as_deref());
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(
                Cloud::Azure,
                format!("Azure profile required to search DNS for `{}`", q.pattern),
            ));
        }
        let force = args
            .get("refresh")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mut merged = oscar_core::DiscoveryResult::empty(
            &q.pattern,
            q.mode,
            format!("azure.dns:{} profiles", profiles.len()),
        );
        let source = AzureDnsSource;
        let opts = DnsSyncOpts::default();
        for p in profiles {
            let inv = match ensure_dns_inventory(&ctx.config_dir, p, &source, &opts, force).await {
                Ok(inv) => inv,
                Err(e) => {
                    merged.partial = true;
                    merged.notes.push(format!("profile `{}`: {e}", p.id));
                    if let Some(c) = load_dns_cache(&ctx.config_dir, &p.id) {
                        c
                    } else {
                        continue;
                    }
                }
            };
            let mut part = scan_dns_inventory(&inv, &q);
            merged.hits.append(&mut part.hits);
        }
        merged.hits.truncate(q.limit);
        to_tool_result(discovery_tool_result(merged.finalize()))
    }
}

#[async_trait]
impl Tool for AzureDnsInventorySync {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.dns.inventory.sync".into(),
            name: "Sync Azure DNS into unified inventory".into(),
            description: "Live-fetch Azure DNS + Private DNS zones/records via az CLI into DnsInventory cache.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec!["dns".into(), "sync".into(), "inventory".into(), "azure".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" },
                    "include_records": { "type": "boolean", "default": true }
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
                "Azure profile required to sync DNS",
            ));
        }
        let mut opts = DnsSyncOpts::default();
        if let Some(b) = args.get("include_records").and_then(|v| v.as_bool()) {
            opts.include_records = b;
        }
        let source = AzureDnsSource;
        let mut details = Vec::new();
        let mut zones = 0usize;
        for p in profiles {
            match source.sync_dns(p, &opts).await {
                Ok(inv) => {
                    zones += inv.zones.len();
                    let _ = write_dns_cache(&ctx.config_dir, &inv);
                    details.push(format!("{}: {} zones", p.id, inv.zones.len()));
                }
                Err(e) => details.push(format!("{}: ERROR {e}", p.id)),
            }
        }
        ToolResult::success(
            format!("Azure DNS sync: {zones} zones"),
            json!({ "format": "DnsInventory", "zones": zones, "details": details }),
        )
    }
}

fn azure_values(args: &serde_json::Value) -> Result<Vec<String>, ToolResult> {
    let arr = args
        .get("values")
        .or_else(|| args.get("rrdatas"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| ToolResult::error("missing `values` string array"))?;
    let out: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    if out.is_empty() {
        return Err(ToolResult::error("`values` must be non-empty"));
    }
    Ok(out)
}

/// Map record type to az record-set subcommand (a, aaaa, cname, txt, mx, …).
fn azure_rr_subcmd(rtype: &str) -> Result<&'static str, ToolResult> {
    Ok(match rtype.to_ascii_uppercase().as_str() {
        "A" => "a",
        "AAAA" => "aaaa",
        "CNAME" => "cname",
        "TXT" => "txt",
        "MX" => "mx",
        "NS" => "ns",
        "PTR" => "ptr",
        "SRV" => "srv",
        "CAA" => "caa",
        other => {
            return Err(ToolResult::error(format!(
                "unsupported Azure DNS record type `{other}` (supported: A AAAA CNAME TXT MX NS PTR SRV CAA)"
            )));
        }
    })
}

#[async_trait]
impl Tool for AzureDnsRecordCreate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.dns.record.create".into(),
            name: "Create Azure DNS record".into(),
            description: "Create/update an Azure DNS record set via live az network dns record-set (write mode required). Supports public zones; set private=true for private DNS.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Azure],
            capability: Capability::Write,
            tags: vec!["dns".into(), "create".into(), "write".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "resource_group": { "type": "string" },
                    "zone": { "type": "string" },
                    "name": { "type": "string", "description": "Relative record name (e.g. www) or @" },
                    "type": { "type": "string" },
                    "values": { "type": "array", "items": { "type": "string" } },
                    "ttl": { "type": "integer", "default": 300 },
                    "private": { "type": "boolean", "default": false },
                    "profile_id": { "type": "string" }
                },
                "required": ["resource_group", "zone", "name", "type", "values"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        use oscar_identity::{resolve_azure_hints, BinaryInventory};
        use oscar_tools::sync::{run_json_command, which_ok};

        let profiles = ctx.profiles_for(Cloud::Azure, args.get("profile_id").and_then(|v| v.as_str()),
        );
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(Cloud::Azure, "Azure profile required"));
        }
        let profile = profiles[0];
        if !which_ok("az").await {
            return ToolResult::needs_auth(
                auth_for(Cloud::Azure, "az binary not found on PATH").profile(profile.id.clone()),
            );
        }
        let binaries = BinaryInventory::detect();
        if let Err(a) = resolve_azure_hints(profile, &binaries) {
            return ToolResult::needs_auth(a);
        }
        let rg = args
            .get("resource_group")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let zone = args.get("zone").and_then(|v| v.as_str()).unwrap_or("");
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let rtype = args
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_uppercase();
        if rg.is_empty() || zone.is_empty() || name.is_empty() || rtype.is_empty() {
            return ToolResult::error("resource_group, zone, name, type are required");
        }
        let values = match azure_values(&args) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let ttl = args
            .get("ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(300)
            .to_string();
        let private = args
            .get("private")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let family = if private { "private-dns" } else { "dns" };
        let sub = match azure_rr_subcmd(&rtype) {
            Ok(s) => s,
            Err(e) => return e,
        };
        // create record-set shell (ignore already-exists), then add-record for each value
        let cmd: Vec<String> = vec![
            "network".into(),
            family.into(),
            "record-set".into(),
            sub.into(),
            "create".into(),
            "-g".into(),
            rg.into(),
            "-z".into(),
            zone.into(),
            "-n".into(),
            name.into(),
            "--ttl".into(),
            ttl,
            "-o".into(),
            "json".into(),
        ];
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        let _ = run_json_command("az", &refs).await; // ignore exists errors
        let mut last_ok = None;
        for val in &values {
            let mut add: Vec<String> = vec![
                "network".into(),
                family.into(),
                "record-set".into(),
                sub.into(),
                "add-record".into(),
                "-g".into(),
                rg.into(),
                "-z".into(),
                zone.into(),
                "-n".into(),
                name.into(),
                "-o".into(),
                "json".into(),
            ];
            match sub {
                "a" => {
                    add.push("--ipv4-address".into());
                    add.push(val.clone());
                }
                "aaaa" => {
                    add.push("--ipv6-address".into());
                    add.push(val.clone());
                }
                "cname" => {
                    add.push("--cname".into());
                    add.push(val.clone());
                }
                "txt" => {
                    add.push("--value".into());
                    add.push(val.clone());
                }
                "mx" => {
                    // "10 mail.example.com"
                    let mut parts = val.split_whitespace();
                    let pref = parts.next().unwrap_or("10");
                    let exch = parts.next().unwrap_or(val);
                    add.push("--preference".into());
                    add.push(pref.into());
                    add.push("--exchange".into());
                    add.push(exch.into());
                }
                "caa" => {
                    // "0 issue letsencrypt.org"  or  "0 issuewild ;"
                    let mut parts = val.split_whitespace();
                    let flags = parts.next().unwrap_or("0");
                    let tag = parts.next().unwrap_or("issue");
                    let value: String = parts.collect::<Vec<_>>().join(" ");
                    let value = if value.is_empty() { ";".into() } else { value };
                    add.push("--flags".into());
                    add.push(flags.into());
                    add.push("--tag".into());
                    add.push(tag.into());
                    add.push("--value".into());
                    add.push(value);
                }
                _ => {
                    add.push("--value".into());
                    add.push(val.clone());
                }
            }
            let arefs: Vec<&str> = add.iter().map(|s| s.as_str()).collect();
            match run_json_command("az", &arefs).await {
                Ok(v) => last_ok = Some(v),
                Err(e) => {
                    return ToolResult::from_error_text(
                        Cloud::Azure,
                        Some(&profile.id),
                        e.to_string(),
                    );
                }
            }
        }
        ToolResult::success(
            format!(
                "Azure DNS {rtype} {name} in zone {zone} ({} value(s))",
                values.len()
            ),
            json!({
                "cloud": "azure",
                "action": "create",
                "resource_group": rg,
                "zone": zone,
                "name": name,
                "type": rtype,
                "values": values,
                "private": private,
                "raw": last_ok,
            }),
        )
    }
}

#[async_trait]
impl Tool for AzureDnsRecordDelete {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.dns.record.delete".into(),
            name: "Delete Azure DNS record".into(),
            description: "Delete an Azure DNS record set via live az network dns record-set delete (write mode required).".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Azure],
            capability: Capability::Write,
            tags: vec!["dns".into(), "delete".into(), "write".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "resource_group": { "type": "string" },
                    "zone": { "type": "string" },
                    "name": { "type": "string" },
                    "type": { "type": "string" },
                    "private": { "type": "boolean", "default": false },
                    "profile_id": { "type": "string" }
                },
                "required": ["resource_group", "zone", "name", "type"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        use oscar_identity::{resolve_azure_hints, BinaryInventory};
        use oscar_tools::sync::{run_json_command, which_ok};

        let profiles = ctx.profiles_for(Cloud::Azure, args.get("profile_id").and_then(|v| v.as_str()),
        );
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(Cloud::Azure, "Azure profile required"));
        }
        let profile = profiles[0];
        if !which_ok("az").await {
            return ToolResult::needs_auth(
                auth_for(Cloud::Azure, "az binary not found on PATH").profile(profile.id.clone()),
            );
        }
        let binaries = BinaryInventory::detect();
        if let Err(a) = resolve_azure_hints(profile, &binaries) {
            return ToolResult::needs_auth(a);
        }
        let rg = args
            .get("resource_group")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let zone = args.get("zone").and_then(|v| v.as_str()).unwrap_or("");
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let rtype = args
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_uppercase();
        if rg.is_empty() || zone.is_empty() || name.is_empty() || rtype.is_empty() {
            return ToolResult::error("resource_group, zone, name, type are required");
        }
        let private = args
            .get("private")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let family = if private { "private-dns" } else { "dns" };
        let sub = match azure_rr_subcmd(&rtype) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let cmd = [
            "network",
            family,
            "record-set",
            sub,
            "delete",
            "-g",
            rg,
            "-z",
            zone,
            "-n",
            name,
            "--yes",
            "-o",
            "json",
        ];
        match run_json_command("az", &cmd).await {
            Ok(v) => ToolResult::success(
                format!("Azure DNS delete {rtype} {name} in zone {zone}"),
                json!({
                    "cloud": "azure",
                    "action": "delete",
                    "resource_group": rg,
                    "zone": zone,
                    "name": name,
                    "type": rtype,
                    "private": private,
                    "raw": v,
                }),
            ),
            Err(e) => {
                let text = e.to_string();
                // empty response on success is common
                if text.is_empty() || text.contains("None") {
                    ToolResult::success(
                        format!("Azure DNS delete {rtype} {name} in zone {zone}"),
                        json!({
                            "cloud": "azure",
                            "action": "delete",
                            "resource_group": rg,
                            "zone": zone,
                            "name": name,
                            "type": rtype,
                            "private": private,
                        }),
                    )
                } else {
                    ToolResult::from_error_text(Cloud::Azure, Some(&profile.id), text)
                }
            }
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkPathTroubleshoot {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.path.troubleshoot".into(),
            name: "Azure Network Watcher connection troubleshoot".into(),
            description: "Azure Network Watcher connection troubleshoot (D3: agentless-style when source is a resource id via --source-resource; otherwise source-address). Live az network watcher test-connectivity. Prefer azure.network.pattern.search for subnet/IP discovery.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "path".into(),
                "network-watcher".into(),
                "agentless".into(),
                "connection-troubleshoot".into(),
                "connectivity".into(),
                "connectivity-test".into(),
                "status".into(),
                "analyze".into(),
                "troubleshoot".into(),
                "reachability".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "source": { "type": "string" },
                    "destination": { "type": "string" },
                    "protocol": { "type": "string" },
                    "destination_port": { "type": "integer" },
                    "profile_id": { "type": "string" }
                },
                "required": ["source", "destination"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let source = args.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let dest = args.get("destination").and_then(|v| v.as_str()).unwrap_or("");
        if source.is_empty() || dest.is_empty() {
            return ToolResult::error("source and destination are required");
        }
        let profiles = ctx.profiles_for(Cloud::Azure, args.get("profile_id").and_then(|v| v.as_str()),
        );
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(
                Cloud::Azure,
                "Azure credentials required for Network Watcher",
            ));
        }
        let profile = profiles[0];
        use oscar_identity::{resolve_azure_hints, BinaryInventory};
        use oscar_tools::sync::{run_json_command, which_ok};
        if !which_ok("az").await {
            return ToolResult::needs_auth(
                auth_for(Cloud::Azure, "az binary not found on PATH").profile(profile.id.clone()),
            );
        }
        let binaries = BinaryInventory::detect();
        if let Err(a) = resolve_azure_hints(profile, &binaries) {
            return ToolResult::needs_auth(a);
        }
        // Prefer agentless-style connectivity test when source is a resource id.
        let port = args
            .get("destination_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(443)
            .to_string();
        let mut cmd: Vec<String> = vec![
            "network".into(),
            "watcher".into(),
            "test-connectivity".into(),
            "--dest-address".into(),
            dest.into(),
            "--dest-port".into(),
            port,
            "-o".into(),
            "json".into(),
        ];
        if source.starts_with("/subscriptions/") {
            cmd.push("--source-resource".into());
            cmd.push(source.into());
        } else {
            cmd.push("--source-address".into());
            cmd.push(source.into());
        }
        let refs: Vec<&str> = cmd.iter().map(|s: &String| s.as_str()).collect();
        match run_json_command("az", &refs).await {
            Ok(v) => {
                let state = v
                    .pointer("/connectionStatus")
                    .or_else(|| v.get("connectionStatus"))
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "unknown".into());
                ToolResult::success(
                    format!("Azure connection troubleshoot {source} → {dest}: {state}"),
                    json!({
                        "format": "PathTraceResult",
                        "cloud": "azure",
                        "source": source,
                        "destination": dest,
                        "native": v,
                    }),
                )
            }
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&profile.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for AzureNetworkNextHop {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.next_hop".into(),
            name: "Azure Network Watcher next hop".into(),
            description: "Next hop type/IP for traffic leaving a VM.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "next-hop".into(),
                "routing".into(),
                "route".into(),
                "status".into(),
                "analyze".into(),
                "troubleshoot".into(),
                "connectivity".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "vm_id": { "type": "string" },
                    "source_ip": { "type": "string" },
                    "destination_ip": { "type": "string" },
                    "profile_id": { "type": "string" }
                },
                "required": ["destination_ip"]
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
                "Azure credentials required for next hop",
            ));
        }
        let profile = profiles[0];
        use oscar_identity::{resolve_azure_hints, BinaryInventory};
        use oscar_tools::sync::{run_json_command, which_ok};
        if !which_ok("az").await {
            return ToolResult::needs_auth(
                auth_for(Cloud::Azure, "az binary not found").profile(profile.id.clone()),
            );
        }
        let binaries = BinaryInventory::detect();
        if let Err(a) = resolve_azure_hints(profile, &binaries) {
            return ToolResult::needs_auth(a);
        }
        let dest = args
            .get("destination_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if dest.is_empty() {
            return ToolResult::error("destination_ip is required");
        }
        let mut cmd: Vec<String> = vec![
            "network".into(),
            "watcher".into(),
            "show-next-hop".into(),
            "--dest-ip".into(),
            dest.into(),
            "-o".into(),
            "json".into(),
        ];
        if let Some(src) = args.get("source_ip").and_then(|v| v.as_str()) {
            cmd.push("--source-ip".into());
            cmd.push(src.into());
        }
        if let Some(vm) = args.get("vm_id").and_then(|v| v.as_str()) {
            cmd.push("--vm".into());
            cmd.push(vm.into());
        }
        let refs: Vec<&str> = cmd.iter().map(|s: &String| s.as_str()).collect();
        match run_json_command("az", &refs).await {
            Ok(v) => ToolResult::success(
                format!("Azure next hop toward {dest}"),
                json!({ "format": "NextHop", "destination_ip": dest, "native": v }),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Azure, Some(&profile.id), e.to_string()),
        }
    }
}

async fn azure_net_pattern(
    args: serde_json::Value,
    ctx: &ToolContext,
    kinds_filter: Option<&[&str]>,
) -> ToolResult {
    let q = match PatternQuery::from_args(&args) {
        Ok(q) => q,
        Err(e) => return ToolResult::error(e),
    };
    let profiles = ctx.profiles_for(Cloud::Azure, q.profile_id.as_deref());
    if profiles.is_empty() {
        return ToolResult::needs_auth(auth_for(
            Cloud::Azure,
            format!("Azure profile required for network search `{}`", q.pattern),
        ));
    }
    let force = args
        .get("refresh")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut merged = oscar_core::DiscoveryResult::empty(
        &q.pattern,
        q.mode,
        format!("azure.network:{} profiles", profiles.len()),
    );
    let source = AzureNetworkSource;
    for p in profiles {
        match ensure_network_inventory(
            &ctx.config_dir,
            p,
            &source,
            q.region.as_deref(),
            force,
        )
        .await
        {
            Ok(inv) => {
                let mut part = scan_network_inventory(&inv, &q);
                if let Some(filters) = kinds_filter {
                    part.hits.retain(|h| {
                        let k = h.kind.to_string();
                        filters.iter().any(|f| k == *f)
                    });
                }
                merged.hits.append(&mut part.hits);
            }
            Err(e) => {
                merged.partial = true;
                merged.notes.push(format!("profile `{}`: {e}", p.id));
                if let Some(inv) = load_network_cache(&ctx.config_dir, &p.id, q.region.as_deref()) {
                    let mut part = scan_network_inventory(&inv, &q);
                    if let Some(filters) = kinds_filter {
                        part.hits.retain(|h| {
                            let k = h.kind.to_string();
                            filters.iter().any(|f| k == *f)
                        });
                    }
                    merged.hits.append(&mut part.hits);
                }
            }
        }
    }
    merged.hits.truncate(q.limit);
    to_tool_result(discovery_tool_result(merged.finalize()))
}

#[async_trait]
impl Tool for AzureNetworkInventorySync {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.inventory.sync".into(),
            name: "Sync VNet/NSG/routes/Functions into NetworkInventory".into(),
            description: "Live-fetch Azure VNets, subnets, public IPs, NICs, NSGs, route tables, and Function Apps via az; map to unified NetworkInventory for pattern search.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "sync".into(),
                "inventory".into(),
                "vnet".into(),
                "subnet".into(),
                "nsg".into(),
                "route-table".into(),
                "function".into(),
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
        let profiles = ctx.profiles_for(Cloud::Azure, args.get("profile_id").and_then(|v| v.as_str()),
        );
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(
                Cloud::Azure,
                "Azure profile required to sync network inventory",
            ));
        }
        let region = args.get("region").and_then(|v| v.as_str());
        let source = AzureNetworkSource;
        let mut details = Vec::new();
        let mut vpcs = 0usize;
        let mut subnets = 0usize;
        let mut addrs = 0usize;
        let mut sgs = 0usize;
        let mut rts = 0usize;
        let mut routes = 0usize;
        let mut funcs = 0usize;
        for p in profiles {
            let r = region.or(p.default_region.as_deref());
            match source.sync_network(p, r).await {
                Ok(inv) => {
                    vpcs += inv.vpcs.len();
                    subnets += inv.subnets.len();
                    addrs += inv.addresses.len();
                    sgs += inv.security_groups.len();
                    rts += inv.route_tables.len();
                    routes += inv.routes.len();
                    funcs += inv.functions.len();
                    let _ = write_network_cache(&ctx.config_dir, &inv);
                    details.push(format!(
                        "{}: vnets={} subnets={} addresses={} nsgs={} route_tables={} routes={} functions={}",
                        p.id,
                        inv.vpcs.len(),
                        inv.subnets.len(),
                        inv.addresses.len(),
                        inv.security_groups.len(),
                        inv.route_tables.len(),
                        inv.routes.len(),
                        inv.functions.len()
                    ));
                }
                Err(e) => details.push(format!("{}: ERROR {e}", p.id)),
            }
        }
        ToolResult::success(
            format!(
                "Azure network sync: {vpcs} vnets, {subnets} subnets, {addrs} addresses, {sgs} nsgs, {rts} route tables, {routes} routes, {funcs} functions"
            ),
            json!({
                "cloud": "azure",
                "format": "NetworkInventory",
                "vpcs": vpcs,
                "subnets": subnets,
                "addresses": addrs,
                "security_groups": sgs,
                "route_tables": rts,
                "routes": routes,
                "functions": funcs,
                "details": details
            }),
        )
    }
}

#[async_trait]
impl Tool for AzureNetworkPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.pattern.search".into(),
            name: "Pattern search VNets, subnets, NSGs, routes, Functions".into(),
            description: discovery_blurb(
                "Azure VNets, subnets, addresses, NSGs, route tables/routes, and Function Apps",
            ),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "pattern".into(),
                "search".into(),
                "subnet".into(),
                "vnet".into(),
                "ip".into(),
                "cidr".into(),
                "nsg".into(),
                "route".into(),
                "function".into(),
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
        azure_net_pattern(args, ctx, None).await
    }
}

#[async_trait]
impl Tool for AzureNetworkSubnetPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.subnet.pattern".into(),
            name: "Pattern search Azure subnets".into(),
            description: discovery_blurb("Azure subnets — partial CIDR or name"),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec!["subnet".into(), "pattern".into(), "cidr".into(), "partial".into()],
            input_schema: json!({
                "type": "object",
                "properties": pattern_properties(),
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        azure_net_pattern(args, ctx, Some(&["subnet"])).await
    }
}

#[async_trait]
impl Tool for AzureNetworkVnetPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.vnet.pattern".into(),
            name: "Pattern search Azure VNets".into(),
            description: discovery_blurb("Azure virtual networks (VNets) by name, id, or address space CIDR"),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec!["vnet".into(), "vpc".into(), "pattern".into(), "search".into(), "network".into(), "partial".into()],
            input_schema: json!({
                "type": "object",
                "properties": pattern_properties(),
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        azure_net_pattern(args, ctx, Some(&["vpc"])).await
    }
}

#[async_trait]
impl Tool for AzureNetworkNsgPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.nsg.pattern".into(),
            name: "Pattern search Azure NSGs".into(),
            description: discovery_blurb(
                "Azure network security groups (NSGs) by name or resource id",
            ),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "nsg".into(),
                "security-group".into(),
                "pattern".into(),
                "search".into(),
                "network".into(),
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
        azure_net_pattern(args, ctx, Some(&["security_group"])).await
    }
}

#[async_trait]
impl Tool for AzureNetworkRouteTablePattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.route_table.pattern".into(),
            name: "Pattern search Azure route tables".into(),
            description: discovery_blurb(
                "Azure route tables by name, id, destination prefix, or next hop",
            ),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec!["route-table".into(), "udr".into(), "pattern".into(), "search".into(), "network".into(), "partial".into()],
            input_schema: json!({
                "type": "object",
                "properties": pattern_properties(),
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        azure_net_pattern(args, ctx, Some(&["route_table"])).await
    }
}

#[async_trait]
impl Tool for AzureNetworkRoutePattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.route.pattern".into(),
            name: "Pattern search Azure routes".into(),
            description: discovery_blurb(
                "Azure UDR routes by name, address prefix, or next-hop type/IP",
            ),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec!["route".into(), "udr".into(), "pattern".into(), "search".into(), "cidr".into(), "network".into(), "partial".into()],
            input_schema: json!({
                "type": "object",
                "properties": pattern_properties(),
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        azure_net_pattern(args, ctx, Some(&["route"])).await
    }
}

#[async_trait]
impl Tool for AzureComputeFunctionPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.compute.function.pattern".into(),
            name: "Pattern search Azure Function Apps".into(),
            description: discovery_blurb(
                "Azure Function Apps by name, hostname, kind/runtime, or VNet subnet id",
            ),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "function".into(),
                "functionapp".into(),
                "compute".into(),
                "pattern".into(),
                "search".into(),
                "serverless".into(),
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
        azure_net_pattern(args, ctx, Some(&["function"])).await
    }
}

#[async_trait]
impl Tool for AzureNetworkPeeringPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.peering.pattern".into(),
            name: "Pattern search VNet peerings".into(),
            description: discovery_blurb("Azure VNet peerings by name, remote VNet, or peering state"),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec!["peering".into(), "vnet".into(), "pattern".into(), "search".into(), "network".into(), "partial".into()],
            input_schema: json!({"type":"object","properties":pattern_properties(),"required":["pattern"]}),
            output_schema: None,
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        azure_net_pattern(args, ctx, Some(&["peering"])).await
    }
}

#[async_trait]
impl Tool for AzureNetworkVpnPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.vpn.pattern".into(),
            name: "Pattern search VPN / VNet gateways".into(),
            description: discovery_blurb("Azure virtual network gateways (VPN/ExpressRoute gateway) by name or type"),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec!["vpn".into(), "vnet-gateway".into(), "pattern".into(), "search".into(), "hybrid".into(), "network".into()],
            input_schema: json!({"type":"object","properties":pattern_properties(),"required":["pattern"]}),
            output_schema: None,
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        azure_net_pattern(args, ctx, Some(&["vpn"])).await
    }
}

#[async_trait]
impl Tool for AzureNetworkHybridPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.hybrid.pattern".into(),
            name: "Pattern search ExpressRoute circuits".into(),
            description: discovery_blurb("Azure ExpressRoute circuits (hybrid on-prem connectivity)"),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec!["expressroute".into(), "hybrid".into(), "interconnect".into(), "pattern".into(), "search".into(), "network".into()],
            input_schema: json!({"type":"object","properties":pattern_properties(),"required":["pattern"]}),
            output_schema: None,
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        azure_net_pattern(args, ctx, Some(&["hybrid_connection"])).await
    }
}

#[async_trait]
impl Tool for AzureNetworkEndpointPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.endpoint.pattern".into(),
            name: "Pattern search Private Endpoints".into(),
            description: discovery_blurb("Azure Private Endpoints (Private Link) by name, subnet, or service"),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec!["private-endpoint".into(), "privatelink".into(), "pattern".into(), "search".into(), "network".into(), "private".into()],
            input_schema: json!({"type":"object","properties":pattern_properties(),"required":["pattern"]}),
            output_schema: None,
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        azure_net_pattern(args, ctx, Some(&["private_endpoint"])).await
    }
}

#[async_trait]
impl Tool for AzureNetworkNatPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.nat.pattern".into(),
            name: "Pattern search NAT gateways".into(),
            description: discovery_blurb("Azure NAT gateways by name or location"),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec!["nat".into(), "nat-gateway".into(), "pattern".into(), "search".into(), "network".into(), "egress".into()],
            input_schema: json!({"type":"object","properties":pattern_properties(),"required":["pattern"]}),
            output_schema: None,
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        azure_net_pattern(args, ctx, Some(&["nat_gateway"])).await
    }
}

#[async_trait]
impl Tool for AzureNetworkServicePattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.service.pattern".into(),
            name: "Pattern search all Azure network fabric services".into(),
            description: discovery_blurb(
                "Azure VNet peering, VPN gateways, ExpressRoute, Private Endpoints, NAT — broad fabric search",
            ),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "network".into(), "service".into(), "pattern".into(), "search".into(), "peering".into(),
                "vpn".into(), "expressroute".into(), "private-endpoint".into(), "nat".into(), "partial".into(),
            ],
            input_schema: json!({"type":"object","properties":pattern_properties(),"required":["pattern"]}),
            output_schema: None,
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        azure_net_pattern(
            args,
            ctx,
            Some(&[
                "peering",
                "vpn",
                "hybrid_connection",
                "private_endpoint",
                "nat_gateway",
                "transit_gateway",
                "network_share",
            ]),
        )
        .await
    }
}

#[async_trait]
impl Tool for AzureNetworkIpLocate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "azure.network.ip.locate".into(),
            name: "Locate IP in Azure networks".into(),
            description: "Find VNet/subnet containing an IP or partial IP fragment.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Azure],
            capability: Capability::Read,
            tags: vec!["ip".into(), "locate".into(), "pattern".into(), "subnet".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string" },
                    "ip": { "type": "string" },
                    "profile_id": { "type": "string" },
                    "region": { "type": "string" },
                    "limit": { "type": "integer" }
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
        azure_net_pattern(args, ctx, None).await
    }
}
