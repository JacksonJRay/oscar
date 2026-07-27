//! GCP tools: Cloud DNS + network inventory + Connectivity Tests + IAM + pattern discovery.

mod iam;
mod resolver;
mod sync_dns;
mod sync_network;
mod sync_resolver;

pub use sync_dns::GcpDnsSource;
pub use sync_network::GcpNetworkSource;
pub use sync_resolver::{DnsResolverInventorySource as GcpDnsResolverInventorySource, GcpDnsResolverSource};

use async_trait::async_trait;
use oscar_core::{Capability, Cloud, PatternQuery, ToolDomain};
use oscar_tools::sync::{DnsInventorySource, NetworkInventorySource};
use oscar_tools::{
    auth_for, discovery_blurb, discovery_tool_result, ensure_dns_inventory, ensure_network_inventory,
    load_dns_cache, load_network_cache, pattern_properties, resolve_profiles, scan_dns_inventory,
    scan_network_inventory, to_tool_result, write_dns_cache, write_network_cache, DnsSyncOpts,
    Tool, ToolContext, ToolMeta, ToolRegistry, ToolResult,
};
use serde_json::json;
use std::sync::Arc;

pub fn register(registry: &mut ToolRegistry) {
    registry.register(Arc::new(GcpDnsZonesList));
    registry.register(Arc::new(GcpDnsRecordLookup));
    registry.register(Arc::new(GcpDnsPatternSearch));
    registry.register(Arc::new(GcpDnsInventorySync));
    registry.register(Arc::new(GcpDnsRecordCreate));
    registry.register(Arc::new(GcpDnsRecordDelete));
    registry.register(Arc::new(GcpConnectivityTest));
    registry.register(Arc::new(GcpNetworkPatternSearch));
    registry.register(Arc::new(GcpNetworkSubnetPattern));
    registry.register(Arc::new(GcpNetworkIpLocate));
    registry.register(Arc::new(GcpNetworkInventorySync));
    // Track C — DNS policies / forwarding / response policies
    registry.register(Arc::new(resolver::GcpDnsResolverInventorySync));
    registry.register(Arc::new(resolver::GcpDnsPolicyPatternSearch));
    iam::register_iam(registry);
}

struct GcpNetworkInventorySync;

struct GcpDnsZonesList;
struct GcpDnsRecordLookup;
struct GcpDnsPatternSearch;
struct GcpDnsInventorySync;
struct GcpDnsRecordCreate;
struct GcpDnsRecordDelete;
struct GcpConnectivityTest;
struct GcpNetworkPatternSearch;
struct GcpNetworkSubnetPattern;
struct GcpNetworkIpLocate;

#[async_trait]
impl Tool for GcpDnsZonesList {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.dns.zones.list".into(),
            name: "List Cloud DNS managed zones".into(),
            description: "List public/private Cloud DNS zones. Prefer gcp.dns.pattern.search for name fragments.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Gcp],
            capability: Capability::Read,
            tags: vec!["dns".into(), "zones".into(), "list".into(), "cloud-dns".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" },
                    "project": { "type": "string" }
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
                "GCP credentials required to list Cloud DNS zones",
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
impl Tool for GcpDnsRecordLookup {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.dns.record.lookup".into(),
            name: "Lookup Cloud DNS record".into(),
            description: "Record lookup; use gcp.dns.pattern.search for partial/glob discovery.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Gcp],
            capability: Capability::Read,
            tags: vec!["dns".into(), "record".into(), "lookup".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
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
        }
        GcpDnsPatternSearch.execute(a, ctx).await
    }
}

#[async_trait]
impl Tool for GcpDnsPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.dns.pattern.search".into(),
            name: "Pattern search Cloud DNS zones & records".into(),
            description: discovery_blurb("GCP Cloud DNS zones and records (public + private)"),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Gcp],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "pattern".into(),
                "search".into(),
                "discover".into(),
                "partial".into(),
                "glob".into(),
                "private".into(),
                "public".into(),
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
            return ToolResult::needs_auth(auth_for(
                Cloud::Gcp,
                format!("GCP profile required to search DNS for `{}`", q.pattern),
            ));
        }
        let force = args
            .get("refresh")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mut merged = oscar_core::DiscoveryResult::empty(
            &q.pattern,
            q.mode,
            format!("gcp.dns:{} profiles", profiles.len()),
        );
        let source = GcpDnsSource;
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
impl Tool for GcpDnsInventorySync {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.dns.inventory.sync".into(),
            name: "Sync Cloud DNS into unified DNS inventory".into(),
            description: "Live-fetch GCP Cloud DNS managed zones and record sets via gcloud, map to unified DnsInventory, write cache for pattern search.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Gcp],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "sync".into(),
                "inventory".into(),
                "cloud-dns".into(),
                "cache".into(),
            ],
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
        let profiles = resolve_profiles(
            &ctx.profiles,
            Cloud::Gcp,
            args.get("profile_id").and_then(|v| v.as_str()),
        );
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(
                Cloud::Gcp,
                "GCP profile required (account_ref = project id)",
            ));
        }
        let mut opts = DnsSyncOpts::default();
        if let Some(b) = args.get("include_records").and_then(|v| v.as_bool()) {
            opts.include_records = b;
        }
        let source = GcpDnsSource;
        let mut details = Vec::new();
        let mut zones = 0usize;
        let mut records = 0usize;
        for p in profiles {
            match source.sync_dns(p, &opts).await {
                Ok(inv) => {
                    zones += inv.zones.len();
                    records += inv.zones.iter().map(|z| z.records.len()).sum::<usize>();
                    let _ = write_dns_cache(&ctx.config_dir, &inv);
                    details.push(format!("{}: {} zones", p.id, inv.zones.len()));
                }
                Err(e) => details.push(format!("{}: ERROR {e}", p.id)),
            }
        }
        ToolResult::success(
            format!("GCP DNS sync: {zones} zones, {records} records"),
            json!({
                "cloud": "gcp",
                "format": "DnsInventory",
                "zones": zones,
                "records": records,
                "details": details
            }),
        )
    }
}

fn gcp_rrdatas(args: &serde_json::Value) -> Result<Vec<String>, ToolResult> {
    let arr = args
        .get("rrdatas")
        .or_else(|| args.get("values"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| ToolResult::error("missing `rrdatas` (or `values`) string array"))?;
    let out: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    if out.is_empty() {
        return Err(ToolResult::error("`rrdatas` must be non-empty"));
    }
    Ok(out)
}

fn gcp_project_profile<'a>(
    ctx: &'a ToolContext,
    profile_id: Option<&str>,
) -> Result<&'a oscar_identity::Profile, ToolResult> {
    let profiles = resolve_profiles(&ctx.profiles, Cloud::Gcp, profile_id);
    profiles.first().copied().ok_or_else(|| {
        ToolResult::needs_auth(auth_for(
            Cloud::Gcp,
            "No GCP profile — oscar profiles add --cloud gcp … or gcloud auth",
        ))
    })
}

#[async_trait]
impl Tool for GcpDnsRecordCreate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.dns.record.create".into(),
            name: "Create Cloud DNS record".into(),
            description: "Create a Cloud DNS record set via live gcloud dns record-sets create (write mode required).".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Gcp],
            capability: Capability::Write,
            tags: vec!["dns".into(), "create".into(), "write".into(), "clouddns".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "zone": { "type": "string", "description": "Managed zone name" },
                    "name": { "type": "string", "description": "DNS name (FQDN preferred)" },
                    "type": { "type": "string" },
                    "rrdatas": { "type": "array", "items": { "type": "string" } },
                    "ttl": { "type": "integer", "default": 300 },
                    "project": { "type": "string" },
                    "profile_id": { "type": "string" }
                },
                "required": ["zone", "name", "type", "rrdatas"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        use oscar_identity::{resolve_gcp_hints, BinaryInventory};
        use oscar_tools::sync::{gcloud_project_args, run_json_command, which_ok};

        let profile = match gcp_project_profile(ctx, args.get("profile_id").and_then(|v| v.as_str()))
        {
            Ok(p) => p,
            Err(e) => return e,
        };
        if !which_ok("gcloud").await {
            return ToolResult::needs_auth(auth_for(Cloud::Gcp, "gcloud binary not found on PATH"));
        }
        let binaries = BinaryInventory::detect();
        if let Err(a) = resolve_gcp_hints(profile, &binaries) {
            return ToolResult::needs_auth(a);
        }
        let zone = args.get("zone").and_then(|v| v.as_str()).unwrap_or("");
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let rtype = args
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_uppercase();
        if zone.is_empty() || name.is_empty() || rtype.is_empty() {
            return ToolResult::error("zone, name, and type are required");
        }
        let rrdatas = match gcp_rrdatas(&args) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let ttl = args
            .get("ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(300)
            .to_string();
        let rr = rrdatas.join(",");
        let mut cmd: Vec<String> = vec![
            "dns".into(),
            "record-sets".into(),
            "create".into(),
            name.into(),
            "--rrdatas".into(),
            rr,
            "--type".into(),
            rtype.clone(),
            "--ttl".into(),
            ttl,
            "--zone".into(),
            zone.into(),
            "--format=json".into(),
        ];
        if let Some(p) = args.get("project").and_then(|v| v.as_str()) {
            cmd.push(format!("--project={p}"));
        } else {
            for a in gcloud_project_args(profile) {
                cmd.push(a);
            }
        }
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("gcloud", &refs).await {
            Ok(v) => ToolResult::success(
                format!("GCP Cloud DNS create {rtype} {name} in zone {zone}"),
                json!({
                    "cloud": "gcp",
                    "action": "create",
                    "zone": zone,
                    "name": name,
                    "type": rtype,
                    "rrdatas": rrdatas,
                    "raw": v,
                }),
            ),
            Err(e) => ToolResult::from_error_text(Cloud::Gcp, Some(&profile.id), e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for GcpDnsRecordDelete {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.dns.record.delete".into(),
            name: "Delete Cloud DNS record".into(),
            description: "Delete a Cloud DNS record set via live gcloud dns record-sets delete (write mode required).".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Gcp],
            capability: Capability::Write,
            tags: vec!["dns".into(), "delete".into(), "write".into(), "clouddns".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "zone": { "type": "string" },
                    "name": { "type": "string" },
                    "type": { "type": "string" },
                    "project": { "type": "string" },
                    "profile_id": { "type": "string" }
                },
                "required": ["zone", "name", "type"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        use oscar_identity::{resolve_gcp_hints, BinaryInventory};
        use oscar_tools::sync::{gcloud_project_args, run_json_command, which_ok};

        let profile = match gcp_project_profile(ctx, args.get("profile_id").and_then(|v| v.as_str()))
        {
            Ok(p) => p,
            Err(e) => return e,
        };
        if !which_ok("gcloud").await {
            return ToolResult::needs_auth(auth_for(Cloud::Gcp, "gcloud binary not found on PATH"));
        }
        let binaries = BinaryInventory::detect();
        if let Err(a) = resolve_gcp_hints(profile, &binaries) {
            return ToolResult::needs_auth(a);
        }
        let zone = args.get("zone").and_then(|v| v.as_str()).unwrap_or("");
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let rtype = args
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_uppercase();
        if zone.is_empty() || name.is_empty() || rtype.is_empty() {
            return ToolResult::error("zone, name, and type are required");
        }
        let mut cmd: Vec<String> = vec![
            "dns".into(),
            "record-sets".into(),
            "delete".into(),
            name.into(),
            "--type".into(),
            rtype.clone(),
            "--zone".into(),
            zone.into(),
            "--quiet".into(),
            "--format=json".into(),
        ];
        if let Some(p) = args.get("project").and_then(|v| v.as_str()) {
            cmd.push(format!("--project={p}"));
        } else {
            for a in gcloud_project_args(profile) {
                cmd.push(a);
            }
        }
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match run_json_command("gcloud", &refs).await {
            Ok(v) => ToolResult::success(
                format!("GCP Cloud DNS delete {rtype} {name} in zone {zone}"),
                json!({
                    "cloud": "gcp",
                    "action": "delete",
                    "zone": zone,
                    "name": name,
                    "type": rtype,
                    "raw": v,
                }),
            ),
            Err(e) => {
                // delete often returns empty stdout — treat success exit as ok via text path
                let text = e.to_string();
                if text.to_ascii_lowercase().contains("empty")
                    || text.contains("EOF")
                    || text.is_empty()
                {
                    ToolResult::success(
                        format!("GCP Cloud DNS delete {rtype} {name} in zone {zone}"),
                        json!({
                            "cloud": "gcp",
                            "action": "delete",
                            "zone": zone,
                            "name": name,
                            "type": rtype,
                        }),
                    )
                } else {
                    ToolResult::from_error_text(Cloud::Gcp, Some(&profile.id), text)
                }
            }
        }
    }
}

#[async_trait]
impl Tool for GcpConnectivityTest {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.network.connectivity.test".into(),
            name: "GCP Connectivity Test".into(),
            description: "Network Intelligence Center Connectivity Test. For subnet/IP ownership discovery use gcp.network.pattern.search.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Gcp],
            capability: Capability::Read,
            tags: vec!["network".into(), "path".into(), "connectivity".into()],
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
        let profiles = resolve_profiles(
            &ctx.profiles,
            Cloud::Gcp,
            args.get("profile_id").and_then(|v| v.as_str()),
        );
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(
                Cloud::Gcp,
                "GCP credentials required for Connectivity Tests",
            ));
        }
        let profile = profiles[0];
        use oscar_identity::{resolve_gcp_hints, BinaryInventory};
        use oscar_tools::sync::{run_json_command, which_ok};
        if !which_ok("gcloud").await {
            return ToolResult::needs_auth(
                auth_for(Cloud::Gcp, "gcloud binary not found on PATH")
                    .profile(profile.id.clone()),
            );
        }
        let binaries = BinaryInventory::detect();
        if let Err(a) = resolve_gcp_hints(profile, &binaries) {
            return ToolResult::needs_auth(a);
        }
        let project = &profile.account_ref;
        let protocol = args
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("TCP");
        let port = args
            .get("destination_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(443);
        let name = format!(
            "oscar-ct-{}",
            uuid_like()
        );
        // Create a one-shot connectivity test (IP endpoints).
        let create = [
            "network-management",
            "connectivity-tests",
            "create",
            &name,
            &format!("--source-ip-address={source}"),
            &format!("--destination-ip-address={dest}"),
            &format!("--protocol={protocol}"),
            &format!("--destination-port={port}"),
            &format!("--project={project}"),
            "--format=json",
        ];
        match run_json_command("gcloud", &create).await {
            Ok(created) => {
                // Rerun to get reachability result
                let describe = [
                    "network-management",
                    "connectivity-tests",
                    "describe",
                    &name,
                    &format!("--project={project}"),
                    "--format=json",
                ];
                let detail = run_json_command("gcloud", &describe)
                    .await
                    .unwrap_or(created.clone());
                let reach = detail
                    .pointer("/reachabilityDetails/result")
                    .or_else(|| detail.pointer("/reachabilityDetails/traces/0/endpointInfo"))
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "see native payload".into());
                ToolResult::success(
                    format!("GCP Connectivity Test {name}: {source} → {dest} ({reach})"),
                    json!({
                        "format": "PathTraceResult",
                        "cloud": "gcp",
                        "test_name": name,
                        "source": source,
                        "destination": dest,
                        "native": detail,
                    }),
                )
            }
            Err(e) => {
                let text = e.to_string();
                ToolResult::from_error_text(Cloud::Gcp, Some(&profile.id), text)
            }
        }
    }
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{t:x}")
}

async fn gcp_net_pattern(args: serde_json::Value, ctx: &ToolContext, only_subnet: bool) -> ToolResult {
    let q = match PatternQuery::from_args(&args) {
        Ok(q) => q,
        Err(e) => return ToolResult::error(e),
    };
    let profiles = resolve_profiles(&ctx.profiles, Cloud::Gcp, q.profile_id.as_deref());
    if profiles.is_empty() {
        return ToolResult::needs_auth(auth_for(
            Cloud::Gcp,
            format!("GCP profile required for network search `{}`", q.pattern),
        ));
    }
    let force = args
        .get("refresh")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut merged = oscar_core::DiscoveryResult::empty(
        &q.pattern,
        q.mode,
        format!("gcp.network:{} profiles", profiles.len()),
    );
    let source = GcpNetworkSource;
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
                if only_subnet {
                    part.hits.retain(|h| h.kind.to_string() == "subnet");
                }
                merged.hits.append(&mut part.hits);
            }
            Err(e) => {
                merged.partial = true;
                merged.notes.push(format!("profile `{}`: {e}", p.id));
                if let Some(inv) = load_network_cache(&ctx.config_dir, &p.id, q.region.as_deref()) {
                    let mut part = scan_network_inventory(&inv, &q);
                    if only_subnet {
                        part.hits.retain(|h| h.kind.to_string() == "subnet");
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
impl Tool for GcpNetworkInventorySync {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.network.inventory.sync".into(),
            name: "Sync VPC/subnet/IP into unified NetworkInventory".into(),
            description: "Live-fetch GCP VPC networks, subnets, addresses, and instance IPs via gcloud; map to unified NetworkInventory cache for pattern search.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Gcp],
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
        let profiles = resolve_profiles(
            &ctx.profiles,
            Cloud::Gcp,
            args.get("profile_id").and_then(|v| v.as_str()),
        );
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(
                Cloud::Gcp,
                "GCP profile required to sync network inventory",
            ));
        }
        let region = args.get("region").and_then(|v| v.as_str());
        let source = GcpNetworkSource;
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
                        "{}: vpcs={} subnets={} addresses={}",
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
            format!("GCP network sync: {vpcs} vpcs, {subnets} subnets, {addrs} addresses"),
            json!({
                "cloud": "gcp",
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
impl Tool for GcpNetworkPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.network.pattern.search".into(),
            name: "Pattern search VPC networks, subnets, IPs".into(),
            description: discovery_blurb("GCP VPC networks, subnets, and addresses"),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Gcp],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "pattern".into(),
                "search".into(),
                "subnet".into(),
                "vpc".into(),
                "ip".into(),
                "cidr".into(),
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
        gcp_net_pattern(args, ctx, false).await
    }
}

#[async_trait]
impl Tool for GcpNetworkSubnetPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.network.subnet.pattern".into(),
            name: "Pattern search GCP subnets".into(),
            description: discovery_blurb("GCP subnets — partial CIDR or name"),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Gcp],
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
        gcp_net_pattern(args, ctx, true).await
    }
}

#[async_trait]
impl Tool for GcpNetworkIpLocate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "gcp.network.ip.locate".into(),
            name: "Locate IP in GCP networks".into(),
            description: "Find VPC/subnet containing an IP or partial IP fragment.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Gcp],
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
        gcp_net_pattern(args, ctx, false).await
    }
}
