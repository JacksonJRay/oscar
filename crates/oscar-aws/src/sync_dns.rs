//! AWS Route 53 → unified [`DnsInventory`].

use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_identity::{
    auth_request_from_error, resolve_aws_process_creds, BinaryInventory, Profile,
};
use oscar_tools::inventory::{DnsInventory, DnsRecordEntry, DnsZoneEntry};
use oscar_tools::sync::{run_json_command_with_env, which_ok, DnsInventorySource, DnsSyncOpts};
use tracing::debug;

pub struct AwsDnsSource;

#[async_trait]
impl DnsInventorySource for AwsDnsSource {
    fn cloud(&self) -> Cloud {
        Cloud::Aws
    }

    async fn sync_dns(&self, profile: &Profile, opts: &DnsSyncOpts) -> OscarResult<DnsInventory> {
        if !which_ok("aws").await {
            return Err(OscarError::Tool(
                "AWS CLI (`aws`) not found on PATH — install AWS CLI v2 so oscar can invoke it"
                    .into(),
            ));
        }

        let binaries = BinaryInventory::detect();
        let creds = resolve_aws_process_creds(profile, &binaries).map_err(|a| {
            OscarError::AuthRequired(format!(
                "{} | hints: {}",
                a.reason,
                a.hint_commands.join(" ; ")
            ))
        })?;
        let env: Vec<(String, String)> = creds.env.into_iter().collect();

        let args = ["route53", "list-hosted-zones", "--output", "json"];
        let mut zones_json = run_json_command_with_env("aws", &args, &env)
            .await
            .map_err(|e| map_err(profile, e))?;

        let mut all_zones: Vec<serde_json::Value> = zones_json
            .get("HostedZones")
            .and_then(|z| z.as_array())
            .cloned()
            .unwrap_or_default();

        while zones_json
            .get("IsTruncated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let marker = zones_json
                .get("NextMarker")
                .and_then(|m| m.as_str())
                .ok_or_else(|| OscarError::Tool("Route53 IsTruncated without NextMarker".into()))?;
            let page = [
                "route53",
                "list-hosted-zones",
                "--output",
                "json",
                "--marker",
                marker,
            ];
            zones_json = run_json_command_with_env("aws", &page, &env)
                .await
                .map_err(|e| map_err(profile, e))?;
            if let Some(arr) = zones_json.get("HostedZones").and_then(|z| z.as_array()) {
                all_zones.extend(arr.iter().cloned());
            } else {
                break;
            }
        }

        let mut inv = DnsInventory {
            profile_id: profile.id.clone(),
            cloud: Cloud::Aws,
            zones: Vec::new(),
        };

        let zone_cap = if opts.max_zones_for_records == 0 {
            all_zones.len()
        } else {
            opts.max_zones_for_records.min(all_zones.len())
        };

        for (i, z) in all_zones.iter().enumerate() {
            let id_raw = z.get("Id").and_then(|v| v.as_str()).unwrap_or("");
            let id = id_raw.rsplit('/').next().unwrap_or(id_raw).to_string();
            let name = z
                .get("Name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let private = z
                .pointer("/Config/PrivateZone")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let mut entry = DnsZoneEntry {
                id: id.clone(),
                name: name.clone(),
                private,
                vpc_or_network_ids: vec![],
                records: vec![],
                region: None,
            };

            if private {
                if let Ok(detail) = get_hosted_zone(&env, &id).await {
                    if let Some(vpcs) = detail.pointer("/VPCs").and_then(|v| v.as_array()) {
                        for v in vpcs {
                            if let Some(vpc_id) = v.get("VPCId").and_then(|x| x.as_str()) {
                                entry.vpc_or_network_ids.push(vpc_id.to_string());
                            }
                            if entry.region.is_none() {
                                entry.region = v
                                    .get("VPCRegion")
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());
                            }
                        }
                    }
                }
            }

            if opts.include_records && i < zone_cap {
                match list_records(&env, &id, opts.max_records_per_zone).await {
                    Ok(recs) => entry.records = recs,
                    Err(e) => {
                        debug!(zone = %id, error = %e, "failed to list records for zone");
                    }
                }
            }

            inv.zones.push(entry);
        }

        Ok(inv)
    }
}

fn map_err(profile: &Profile, e: OscarError) -> OscarError {
    let text = e.to_string();
    if let Some(a) = auth_request_from_error(Cloud::Aws, Some(&profile.id), &text) {
        return OscarError::AuthRequired(format!(
            "{} | {}",
            a.reason,
            a.hint_commands.join(" ; ")
        ));
    }
    e
}

async fn get_hosted_zone(
    env: &[(String, String)],
    zone_id: &str,
) -> OscarResult<serde_json::Value> {
    let args = ["route53", "get-hosted-zone", "--id", zone_id, "--output", "json"];
    run_json_command_with_env("aws", &args, env).await
}

async fn list_records(
    env: &[(String, String)],
    zone_id: &str,
    max_records: usize,
) -> OscarResult<Vec<DnsRecordEntry>> {
    let mut args_owned: Vec<String> = vec![
        "route53".into(),
        "list-resource-record-sets".into(),
        "--hosted-zone-id".into(),
        zone_id.into(),
        "--output".into(),
        "json".into(),
    ];
    let a: Vec<&str> = args_owned.iter().map(|s: &String| s.as_str()).collect();
    let mut json = run_json_command_with_env("aws", &a, env).await?;
    let mut out = Vec::new();

    loop {
        if let Some(rrs) = json.get("ResourceRecordSets").and_then(|v| v.as_array()) {
            for rr in rrs {
                let name = rr
                    .get("Name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let rtype = rr
                    .get("Type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let ttl = rr.get("TTL").and_then(|v| v.as_u64()).map(|n| n as u32);
                let mut values = Vec::new();
                if let Some(recs) = rr.get("ResourceRecords").and_then(|v| v.as_array()) {
                    for r in recs {
                        if let Some(v) = r.get("Value").and_then(|x| x.as_str()) {
                            values.push(v.to_string());
                        }
                    }
                }
                if let Some(dns) = rr.pointer("/AliasTarget/DNSName").and_then(|v| v.as_str()) {
                    values.push(format!("ALIAS:{dns}"));
                }
                out.push(DnsRecordEntry {
                    name,
                    record_type: rtype,
                    values,
                    ttl,
                });
                if max_records > 0 && out.len() >= max_records {
                    return Ok(out);
                }
            }
        }

        let truncated = json
            .get("IsTruncated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !truncated {
            break;
        }
        let next_name = json
            .get("NextRecordName")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let next_type = json
            .get("NextRecordType")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let Some(nn) = next_name else { break };
        args_owned = vec![
            "route53".into(),
            "list-resource-record-sets".into(),
            "--hosted-zone-id".into(),
            zone_id.into(),
            "--output".into(),
            "json".into(),
            "--start-record-name".into(),
            nn,
        ];
        if let Some(nt) = next_type {
            args_owned.push("--start-record-type".into());
            args_owned.push(nt);
        }
        let pa: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
        json = run_json_command_with_env("aws", &pa, env).await?;
    }

    Ok(out)
}
