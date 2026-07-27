//! Azure DNS + Private DNS → unified DnsInventory via `az`.

use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_identity::{auth_request_from_error, resolve_azure_hints, BinaryInventory, Profile};
use oscar_tools::inventory::{DnsInventory, DnsRecordEntry, DnsZoneEntry};
use oscar_tools::sync::{run_json_command, which_ok, DnsInventorySource, DnsSyncOpts};

pub struct AzureDnsSource;

#[async_trait]
impl DnsInventorySource for AzureDnsSource {
    fn cloud(&self) -> Cloud {
        Cloud::Azure
    }

    async fn sync_dns(&self, profile: &Profile, opts: &DnsSyncOpts) -> OscarResult<DnsInventory> {
        if !which_ok("az").await {
            return Err(OscarError::Tool(
                "Azure CLI (`az`) not found on PATH — install Azure CLI to sync DNS".into(),
            ));
        }
        let binaries = BinaryInventory::detect();
        resolve_azure_hints(profile, &binaries).map_err(|a| {
            OscarError::AuthRequired(format!("{} | {}", a.reason, a.hint_commands.join(" ; ")))
        })?;

        let mut inv = DnsInventory {
            profile_id: profile.id.clone(),
            cloud: Cloud::Azure,
            zones: Vec::new(),
        };

        // Public Azure DNS zones
        let public = run_json_command(
            "az",
            &["network", "dns", "zone", "list", "-o", "json"],
        )
        .await;
        match public {
            Ok(v) => {
                if let Some(arr) = v.as_array() {
                    for z in arr {
                        let name = z
                            .get("name")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let id = z
                            .get("id")
                            .and_then(|x| x.as_str())
                            .unwrap_or(&name)
                            .to_string();
                        let rg = z
                            .get("resourceGroup")
                            .and_then(|x| x.as_str())
                            .unwrap_or("");
                        let mut entry = DnsZoneEntry {
                            id: id.clone(),
                            name: format!("{name}."),
                            private: false,
                            vpc_or_network_ids: vec![],
                            records: vec![],
                            region: z
                                .get("location")
                                .and_then(|x| x.as_str())
                                .map(|s| s.to_string()),
                        };
                        if opts.include_records && !rg.is_empty() && !name.is_empty() {
                            entry.records =
                                list_public_records(rg, &name, opts.max_records_per_zone).await;
                        }
                        inv.zones.push(entry);
                    }
                }
            }
            Err(e) => {
                let text = e.to_string();
                if let Some(a) = auth_request_from_error(Cloud::Azure, Some(&profile.id), &text) {
                    return Err(OscarError::AuthRequired(format!(
                        "{} | {}",
                        a.reason,
                        a.hint_commands.join(" ; ")
                    )));
                }
                return Err(e);
            }
        }

        // Private DNS zones
        if let Ok(v) = run_json_command(
            "az",
            &["network", "private-dns", "zone", "list", "-o", "json"],
        )
        .await
        {
            if let Some(arr) = v.as_array() {
                for z in arr {
                    let name = z
                        .get("name")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let id = z
                        .get("id")
                        .and_then(|x| x.as_str())
                        .unwrap_or(&name)
                        .to_string();
                    let rg = z
                        .get("resourceGroup")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    let mut entry = DnsZoneEntry {
                        id,
                        name: format!("{name}."),
                        private: true,
                        vpc_or_network_ids: vec![],
                        records: vec![],
                        region: None,
                    };
                    // VNet links
                    if !rg.is_empty() && !name.is_empty() {
                        if let Ok(links) = run_json_command(
                            "az",
                            &[
                                "network",
                                "private-dns",
                                "link",
                                "vnet",
                                "list",
                                "-g",
                                rg,
                                "-z",
                                &name,
                                "-o",
                                "json",
                            ],
                        )
                        .await
                        {
                            if let Some(la) = links.as_array() {
                                for l in la {
                                    if let Some(vid) =
                                        l.get("virtualNetwork").and_then(|v| v.get("id")).and_then(|x| x.as_str())
                                    {
                                        entry.vpc_or_network_ids.push(
                                            vid.rsplit('/').next().unwrap_or(vid).to_string(),
                                        );
                                    }
                                }
                            }
                        }
                        if opts.include_records {
                            entry.records =
                                list_private_records(rg, &name, opts.max_records_per_zone).await;
                        }
                    }
                    inv.zones.push(entry);
                }
            }
        }

        Ok(inv)
    }
}

async fn list_public_records(rg: &str, zone: &str, max: usize) -> Vec<DnsRecordEntry> {
    let mut out = Vec::new();
    let Ok(v) = run_json_command(
        "az",
        &[
            "network",
            "dns",
            "record-set",
            "list",
            "-g",
            rg,
            "-z",
            zone,
            "-o",
            "json",
        ],
    )
    .await
    else {
        return out;
    };
    let Some(arr) = v.as_array() else {
        return out;
    };
    for rr in arr {
        out.push(parse_az_record(rr));
        if max > 0 && out.len() >= max {
            break;
        }
    }
    out
}

async fn list_private_records(rg: &str, zone: &str, max: usize) -> Vec<DnsRecordEntry> {
    let mut out = Vec::new();
    let Ok(v) = run_json_command(
        "az",
        &[
            "network",
            "private-dns",
            "record-set",
            "list",
            "-g",
            rg,
            "-z",
            zone,
            "-o",
            "json",
        ],
    )
    .await
    else {
        return out;
    };
    let Some(arr) = v.as_array() else {
        return out;
    };
    for rr in arr {
        out.push(parse_az_record(rr));
        if max > 0 && out.len() >= max {
            break;
        }
    }
    out
}

fn parse_az_record(rr: &serde_json::Value) -> DnsRecordEntry {
    let name = rr
        .get("fqdn")
        .or_else(|| rr.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let rtype = rr
        .get("type")
        .and_then(|v| v.as_str())
        .map(|s| s.rsplit('/').next().unwrap_or(s).to_string())
        .unwrap_or_else(|| "A".into());
    let ttl = rr.get("ttl").and_then(|v| v.as_u64()).map(|n| n as u32);
    let mut values = Vec::new();
    if let Some(arr) = rr.get("aRecords").and_then(|v| v.as_array()) {
        for a in arr {
            if let Some(ip) = a.get("ipv4Address").and_then(|x| x.as_str()) {
                values.push(ip.to_string());
            }
        }
    }
    if let Some(arr) = rr.get("aaaaRecords").and_then(|v| v.as_array()) {
        for a in arr {
            if let Some(ip) = a.get("ipv6Address").and_then(|x| x.as_str()) {
                values.push(ip.to_string());
            }
        }
    }
    if let Some(arr) = rr.get("cnameRecord").and_then(|v| v.as_object()) {
        if let Some(c) = arr.get("cname").and_then(|x| x.as_str()) {
            values.push(c.to_string());
        }
    }
    DnsRecordEntry {
        name,
        record_type: rtype,
        values,
        ttl,
    }
}
