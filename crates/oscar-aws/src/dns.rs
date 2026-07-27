use crate::aws_runtime::{arg_str, aws_json, require_str, resolve_aws_profile};
use crate::sync_dns::AwsDnsSource;
use async_trait::async_trait;
use oscar_core::{Capability, Cloud, PatternQuery, ToolDomain};
use oscar_tools::{
    auth_for, discovery_blurb, discovery_tool_result, ensure_dns_inventory, load_dns_cache,
    pattern_properties, resolve_profiles, scan_dns_inventory, to_tool_result, write_dns_cache,
    DnsSyncOpts, Tool, ToolContext, ToolMeta, ToolResult,
};
use oscar_tools::sync::DnsInventorySource;
use serde_json::{json, Value};

pub struct AwsDnsZonesList;
pub struct AwsDnsRecordLookup;
pub struct AwsDnsPatternSearch;
pub struct AwsDnsInventorySync;
pub struct AwsDnsRecordCreate;
pub struct AwsDnsRecordDelete;

fn needs_aws(ctx: &ToolContext, reason: &str) -> Option<ToolResult> {
    if resolve_profiles(&ctx.profiles, Cloud::Aws, None).is_empty() {
        Some(ToolResult::needs_auth(auth_for(Cloud::Aws, reason)))
    } else {
        None
    }
}

#[async_trait]
impl Tool for AwsDnsZonesList {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.dns.zones.list".into(),
            name: "List Route 53 hosted zones".into(),
            description: "List public and private Route 53 hosted zones. Prefer aws.dns.pattern.search when looking for a name fragment.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "route53".into(),
                "zones".into(),
                "list".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" },
                    "private_only": { "type": "boolean" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Some(r) = needs_aws(ctx, "No AWS profile — required to list Route 53 zones") {
            return r;
        }
        let profile_id = args.get("profile_id").and_then(|v| v.as_str());
        let profiles = resolve_profiles(&ctx.profiles, Cloud::Aws, profile_id);
        let mut zones = Vec::new();
        let mut partial = false;
        for p in profiles {
            if let Some(inv) = load_dns_cache(&ctx.config_dir, &p.id) {
                for z in inv.zones {
                    zones.push(json!({
                        "profile_id": p.id,
                        "id": z.id,
                        "name": z.name,
                        "private": z.private,
                        "networks": z.vpc_or_network_ids,
                    }));
                }
            } else {
                partial = true;
            }
        }
        let summary = if zones.is_empty() && partial {
            "No cached Route 53 zones — run inventory sync or use aws.dns.pattern.search after sync (live list pending)".into()
        } else {
            format!("{} zone(s) from inventory cache", zones.len())
        };
        let mut r = ToolResult::success(summary, json!({ "zones": zones, "partial": partial }));
        if partial {
            r.diagnostics.push(oscar_core::Diagnostic {
                code: Some("cache_miss".into()),
                message: "DNS inventory cache empty for one or more profiles".into(),
                severity: oscar_core::DiagnosticSeverity::Warning,
            });
        }
        r
    }
}

#[async_trait]
impl Tool for AwsDnsRecordLookup {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.dns.record.lookup".into(),
            name: "Lookup Route 53 record (exact)".into(),
            description: "Exact-ish record lookup by name. For partial/glob discovery use aws.dns.pattern.search.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec!["dns".into(), "route53".into(), "record".into(), "lookup".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "type": { "type": "string" },
                    "profile_id": { "type": "string" },
                    "private": { "type": "boolean" },
                    "vpc_id": { "type": "string" }
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
        // Delegate to pattern search with exact/partial on the name.
        let mut a = args.clone();
        if let Some(obj) = a.as_object_mut() {
            obj.insert("pattern".into(), json!(name));
            obj.insert("mode".into(), json!("partial"));
        }
        AwsDnsPatternSearch.execute(a, ctx).await
    }
}

#[async_trait]
impl Tool for AwsDnsPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            let mut props = pattern_properties();
            if let Some(obj) = props.as_object_mut() {
                obj.insert(
                    "private_only".into(),
                    json!({ "type": "boolean", "description": "Only private hosted zones" }),
                );
                obj.insert(
                    "public_only".into(),
                    json!({ "type": "boolean", "description": "Only public hosted zones" }),
                );
            }
            ToolMeta {
                id: "aws.dns.pattern.search".into(),
                name: "Pattern search Route 53 zones & records".into(),
                description: discovery_blurb(
                    "AWS Route 53 hosted zones and record names/values (public + private)",
                ),
                domain: ToolDomain::Dns,
                clouds: vec![Cloud::Aws],
                capability: Capability::Read,
                tags: vec![
                    "dns".into(),
                    "pattern".into(),
                    "search".into(),
                    "discover".into(),
                    "partial".into(),
                    "glob".into(),
                    "route53".into(),
                    "private".into(),
                    "public".into(),
                    "zone".into(),
                    "record".into(),
                ],
                input_schema: json!({
                    "type": "object",
                    "properties": props,
                    "required": ["pattern"]
                }),
                output_schema: None,
            }
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let q = match PatternQuery::from_args(&args) {
            Ok(q) => q,
            Err(e) => return ToolResult::error(e),
        };
        let profiles = resolve_profiles(&ctx.profiles, Cloud::Aws, q.profile_id.as_deref());
        if profiles.is_empty() {
            return ToolResult::needs_auth(
                auth_for(
                    Cloud::Aws,
                    format!(
                        "AWS profile required to pattern-search DNS for `{}`",
                        q.pattern
                    ),
                )
                .profile(q.profile_id.clone().unwrap_or_else(|| "aws-default".into())),
            );
        }

        let private_only = args
            .get("private_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let public_only = args
            .get("public_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let force = args
            .get("refresh")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mut merged = oscar_core::DiscoveryResult::empty(
            &q.pattern,
            q.mode,
            format!("aws.dns:{} profiles", profiles.len()),
        );
        let source = AwsDnsSource;
        let opts = DnsSyncOpts::default();
        let mut any = false;
        for p in profiles {
            let inv = match ensure_dns_inventory(&ctx.config_dir, p, &source, &opts, force).await {
                Ok(inv) => {
                    any = true;
                    inv
                }
                Err(e) => {
                    merged.partial = true;
                    merged.notes.push(format!("profile `{}`: {e}", p.id));
                    // fall back to stale cache if any
                    if let Some(cached) = load_dns_cache(&ctx.config_dir, &p.id) {
                        any = true;
                        cached
                    } else {
                        continue;
                    }
                }
            };
            let mut inv = inv;
            if private_only {
                inv.zones.retain(|z| z.private);
            }
            if public_only {
                inv.zones.retain(|z| !z.private);
            }
            let mut part = scan_dns_inventory(&inv, &q);
            merged.hits.append(&mut part.hits);
        }
        if !any {
            merged.partial = true;
            merged.notes.push(
                "No AWS DNS inventory. Configure a profile, ensure `aws` CLI works, then run aws.dns.inventory.sync or oscar inventory sync --cloud aws.".into(),
            );
        }
        merged.hits.truncate(q.limit);
        let ready = discovery_tool_result(merged.finalize());
        to_tool_result(ready)
    }
}

#[async_trait]
impl Tool for AwsDnsInventorySync {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.dns.inventory.sync".into(),
            name: "Sync Route 53 into unified DNS inventory".into(),
            description: "Live-fetch AWS Route 53 public/private hosted zones and records via AWS CLI, map to unified DnsInventory, and write ~/.config/oscar/cache/<profile>/dns.json for pattern search.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "sync".into(),
                "inventory".into(),
                "route53".into(),
                "cache".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" },
                    "include_records": { "type": "boolean", "default": true },
                    "max_zones": { "type": "integer", "default": 200 }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profiles = resolve_profiles(
            &ctx.profiles,
            Cloud::Aws,
            args.get("profile_id").and_then(|v| v.as_str()),
        );
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(
                Cloud::Aws,
                "AWS profile required to sync Route 53 inventory",
            ));
        }
        let mut opts = DnsSyncOpts::default();
        if let Some(b) = args.get("include_records").and_then(|v| v.as_bool()) {
            opts.include_records = b;
        }
        if let Some(n) = args.get("max_zones").and_then(|v| v.as_u64()) {
            opts.max_zones_for_records = n as usize;
        }
        let source = AwsDnsSource;
        let mut summaries = Vec::new();
        let mut total_zones = 0usize;
        let mut total_records = 0usize;
        for p in profiles {
            match source.sync_dns(p, &opts).await {
                Ok(inv) => {
                    total_zones += inv.zones.len();
                    total_records += inv.zones.iter().map(|z| z.records.len()).sum::<usize>();
                    if let Err(e) = write_dns_cache(&ctx.config_dir, &inv) {
                        summaries.push(format!("{}: sync ok, cache write failed: {e}", p.id));
                    } else {
                        summaries.push(format!(
                            "{}: {} zones, {} records cached",
                            p.id,
                            inv.zones.len(),
                            inv.zones.iter().map(|z| z.records.len()).sum::<usize>()
                        ));
                    }
                }
                Err(e) => summaries.push(format!("{}: ERROR {e}", p.id)),
            }
        }
        ToolResult::success(
            format!(
                "AWS DNS sync: {total_zones} zones, {total_records} records — {}",
                summaries.join("; ")
            ),
            json!({
                "cloud": "aws",
                "format": "DnsInventory",
                "zones": total_zones,
                "records": total_records,
                "details": summaries
            }),
        )
    }
}

fn values_from_args(args: &Value) -> Result<Vec<String>, ToolResult> {
    let arr = args
        .get("values")
        .or_else(|| args.get("rrdatas"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| ToolResult::error("missing required argument `values` (array of RR strings)"))?;
    let out: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    if out.is_empty() {
        return Err(ToolResult::error("`values` must be a non-empty string array"));
    }
    Ok(out)
}

fn normalize_rr_name(name: &str) -> String {
    let n = name.trim();
    if n.ends_with('.') {
        n.to_string()
    } else {
        format!("{n}.")
    }
}

fn change_batch_json(action: &str, name: &str, rtype: &str, ttl: i64, values: &[String]) -> String {
    let records: Vec<Value> = values.iter().map(|v| json!({ "Value": v })).collect();
    json!({
        "Changes": [{
            "Action": action,
            "ResourceRecordSet": {
                "Name": name,
                "Type": rtype,
                "TTL": ttl,
                "ResourceRecords": records
            }
        }]
    })
    .to_string()
}

/// Alias record change batch (no TTL / ResourceRecords).
fn change_batch_alias_json(
    action: &str,
    name: &str,
    rtype: &str,
    alias_dns: &str,
    alias_zone_id: &str,
    evaluate_target_health: bool,
) -> String {
    let dns = if alias_dns.ends_with('.') {
        alias_dns.to_string()
    } else {
        format!("{alias_dns}.")
    };
    json!({
        "Changes": [{
            "Action": action,
            "ResourceRecordSet": {
                "Name": name,
                "Type": rtype,
                "AliasTarget": {
                    "HostedZoneId": alias_zone_id.trim_start_matches("/hostedzone/"),
                    "DNSName": dns,
                    "EvaluateTargetHealth": evaluate_target_health
                }
            }
        }]
    })
    .to_string()
}

async fn r53_change(
    profile: &oscar_identity::Profile,
    zone_id: &str,
    batch: &str,
) -> Result<Value, ToolResult> {
    let zone = zone_id.trim_start_matches("/hostedzone/");
    aws_json(
        profile,
        &[
            "route53",
            "change-resource-record-sets",
            "--hosted-zone-id",
            zone,
            "--change-batch",
            batch,
        ],
    )
    .await
}

#[async_trait]
impl Tool for AwsDnsRecordCreate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.dns.record.create".into(),
            name: "Create Route 53 record".into(),
            description: "UPSERT a DNS record in Route 53 (write mode). Simple records: values+ttl. Alias records: set alias_dns_name + alias_hosted_zone_id (ELB/CloudFront/S3 website, etc.).".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Aws],
            capability: Capability::Write,
            tags: vec!["dns".into(), "create".into(), "route53".into(), "write".into(), "upsert".into(), "alias".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "zone_id": { "type": "string", "description": "Hosted zone id (Z…)" },
                    "name": { "type": "string", "description": "Record name (FQDN)" },
                    "type": { "type": "string", "description": "A | AAAA | CNAME | TXT | MX | …" },
                    "values": { "type": "array", "items": { "type": "string" }, "description": "RDATA values (omit for alias)" },
                    "ttl": { "type": "integer", "default": 300 },
                    "alias_dns_name": { "type": "string", "description": "Alias target DNS (e.g. dualstack.xxx.elb.amazonaws.com)" },
                    "alias_hosted_zone_id": { "type": "string", "description": "Alias target hosted zone id (ELB/CF canonical zone)" },
                    "evaluate_target_health": { "type": "boolean", "default": false },
                    "profile_id": { "type": "string" }
                },
                "required": ["zone_id", "name", "type"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile(&ctx.profiles, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let zone_id = match require_str(&args, "zone_id") {
            Ok(z) => z,
            Err(e) => return e,
        };
        let name = match require_str(&args, "name") {
            Ok(n) => normalize_rr_name(&n),
            Err(e) => return e,
        };
        let rtype = match require_str(&args, "type") {
            Ok(t) => t.to_ascii_uppercase(),
            Err(e) => return e,
        };
        let alias_dns = arg_str(&args, "alias_dns_name");
        let alias_zone = arg_str(&args, "alias_hosted_zone_id");
        let batch = if let (Some(adns), Some(azone)) = (alias_dns, alias_zone) {
            let eth = args
                .get("evaluate_target_health")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            change_batch_alias_json("UPSERT", &name, &rtype, adns, azone, eth)
        } else {
            let values = match values_from_args(&args) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let ttl = args.get("ttl").and_then(|v| v.as_i64()).unwrap_or(300);
            change_batch_json("UPSERT", &name, &rtype, ttl, &values)
        };
        match r53_change(&profile, &zone_id, &batch).await {
            Ok(v) => {
                let change_id = v
                    .pointer("/ChangeInfo/Id")
                    .and_then(|x| x.as_str())
                    .unwrap_or("—");
                let status = v
                    .pointer("/ChangeInfo/Status")
                    .and_then(|x| x.as_str())
                    .unwrap_or("PENDING");
                let is_alias = alias_dns.is_some();
                ToolResult::success(
                    format!(
                        "Route 53 UPSERT {rtype} {name} {} ({status})",
                        if is_alias { "alias" } else { "records" }
                    ),
                    json!({
                        "cloud": "aws",
                        "action": "UPSERT",
                        "zone_id": zone_id,
                        "name": name,
                        "type": rtype,
                        "alias": is_alias,
                        "alias_dns_name": alias_dns,
                        "alias_hosted_zone_id": alias_zone,
                        "change_id": change_id,
                        "status": status,
                        "raw": v,
                    }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsDnsRecordDelete {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.dns.record.delete".into(),
            name: "Delete Route 53 record".into(),
            description: "DELETE a DNS record from Route 53 (write mode). Auto-fetches the current set when values/alias omitted — supports both simple and AliasTarget records.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Aws],
            capability: Capability::Write,
            tags: vec!["dns".into(), "delete".into(), "route53".into(), "write".into(), "alias".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "zone_id": { "type": "string" },
                    "name": { "type": "string" },
                    "type": { "type": "string" },
                    "values": { "type": "array", "items": { "type": "string" } },
                    "ttl": { "type": "integer", "default": 300 },
                    "alias_dns_name": { "type": "string" },
                    "alias_hosted_zone_id": { "type": "string" },
                    "evaluate_target_health": { "type": "boolean" },
                    "profile_id": { "type": "string" }
                },
                "required": ["zone_id", "name", "type"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile(&ctx.profiles, arg_str(&args, "profile_id")) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let zone_id = match require_str(&args, "zone_id") {
            Ok(z) => z,
            Err(e) => return e,
        };
        let name = match require_str(&args, "name") {
            Ok(n) => normalize_rr_name(&n),
            Err(e) => return e,
        };
        let rtype = match require_str(&args, "type") {
            Ok(t) => t.to_ascii_uppercase(),
            Err(e) => return e,
        };
        let zone = zone_id.trim_start_matches("/hostedzone/");

        // Explicit alias delete
        if let (Some(adns), Some(azone)) = (
            arg_str(&args, "alias_dns_name"),
            arg_str(&args, "alias_hosted_zone_id"),
        ) {
            let eth = args
                .get("evaluate_target_health")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let batch = change_batch_alias_json("DELETE", &name, &rtype, adns, azone, eth);
            return match r53_change(&profile, zone, &batch).await {
                Ok(v) => ToolResult::success(
                    format!("Route 53 DELETE alias {rtype} {name}"),
                    json!({ "cloud": "aws", "action": "DELETE", "alias": true, "raw": v }),
                ),
                Err(e) => e,
            };
        }

        // Explicit simple values
        if let Ok(values) = values_from_args(&args) {
            let ttl = args.get("ttl").and_then(|x| x.as_i64()).unwrap_or(300);
            let batch = change_batch_json("DELETE", &name, &rtype, ttl, &values);
            return match r53_change(&profile, zone, &batch).await {
                Ok(v) => ToolResult::success(
                    format!("Route 53 DELETE {rtype} {name}"),
                    json!({ "cloud": "aws", "action": "DELETE", "values": values, "raw": v }),
                ),
                Err(e) => e,
            };
        }

        // Auto-resolve current record for DELETE
        let listed = match aws_json(
            &profile,
            &[
                "route53",
                "list-resource-record-sets",
                "--hosted-zone-id",
                zone,
                "--start-record-name",
                &name,
                "--start-record-type",
                &rtype,
                "--max-items",
                "1",
            ],
        )
        .await
        {
            Ok(v) => v,
            Err(e) => return e,
        };
        let set = listed
            .get("ResourceRecordSets")
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .cloned();
        let Some(set) = set else {
            return ToolResult::error(format!(
                "no ResourceRecordSet found for {rtype} {name} in zone {zone}"
            ));
        };
        let sn = set.get("Name").and_then(|n| n.as_str()).unwrap_or("");
        let st = set.get("Type").and_then(|t| t.as_str()).unwrap_or("");
        if sn.trim_end_matches('.') != name.trim_end_matches('.') || !st.eq_ignore_ascii_case(&rtype)
        {
            return ToolResult::error(format!(
                "list returned {st} {sn}, not {rtype} {name} — pass values/alias explicitly"
            ));
        }

        let batch = if let Some(alias) = set.get("AliasTarget") {
            let adns = alias
                .get("DNSName")
                .and_then(|d| d.as_str())
                .unwrap_or("");
            let azone = alias
                .get("HostedZoneId")
                .and_then(|z| z.as_str())
                .unwrap_or("");
            let eth = alias
                .get("EvaluateTargetHealth")
                .and_then(|e| e.as_bool())
                .unwrap_or(false);
            if adns.is_empty() || azone.is_empty() {
                return ToolResult::error("AliasTarget missing DNSName/HostedZoneId");
            }
            change_batch_alias_json("DELETE", &name, &rtype, adns, azone, eth)
        } else {
            let ttl = set.get("TTL").and_then(|t| t.as_i64()).unwrap_or(300);
            let values: Vec<String> = set
                .get("ResourceRecords")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|r| {
                            r.get("Value")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                        })
                        .collect()
                })
                .unwrap_or_default();
            if values.is_empty() {
                return ToolResult::error("record has no ResourceRecords to delete");
            }
            change_batch_json("DELETE", &name, &rtype, ttl, &values)
        };

        match r53_change(&profile, zone, &batch).await {
            Ok(v) => {
                let status = v
                    .pointer("/ChangeInfo/Status")
                    .and_then(|x| x.as_str())
                    .unwrap_or("PENDING");
                ToolResult::success(
                    format!("Route 53 DELETE {rtype} {name} ({status})"),
                    json!({
                        "cloud": "aws",
                        "action": "DELETE",
                        "zone_id": zone_id,
                        "name": name,
                        "type": rtype,
                        "status": status,
                        "raw": v,
                    }),
                )
            }
            Err(e) => e,
        }
    }
}
