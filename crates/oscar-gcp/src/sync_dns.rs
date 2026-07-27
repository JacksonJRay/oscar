//! GCP Cloud DNS → unified [`DnsInventory`].
//!
//! Native: `gcloud dns managed-zones list` + `gcloud dns record-sets list`
//! Maps public/private visibility and private network URLs into vpc_or_network_ids.

use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_identity::Profile;
use oscar_tools::inventory::{DnsInventory, DnsRecordEntry, DnsZoneEntry};
use oscar_tools::sync::{
    gcloud_project_args, run_json_command, which_ok, DnsInventorySource, DnsSyncOpts,
};

pub struct GcpDnsSource;

#[async_trait]
impl DnsInventorySource for GcpDnsSource {
    fn cloud(&self) -> Cloud {
        Cloud::Gcp
    }

    async fn sync_dns(&self, profile: &Profile, opts: &DnsSyncOpts) -> OscarResult<DnsInventory> {
        if !which_ok("gcloud").await {
            return Err(OscarError::Tool(
                "gcloud CLI not found on PATH — install Google Cloud SDK to sync Cloud DNS".into(),
            ));
        }
        if profile.account_ref.is_empty() || profile.account_ref == "unknown" {
            return Err(OscarError::Tool(
                "GCP profile needs account_ref set to the GCP project id".into(),
            ));
        }

        let mut args = vec![
            "dns".into(),
            "managed-zones".into(),
            "list".into(),
            "--format=json".into(),
        ];
        args.extend(gcloud_project_args(profile));
        let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let zones_val = run_json_command("gcloud", &a).await?;
        let zones_arr = zones_val
            .as_array()
            .cloned()
            .ok_or_else(|| OscarError::Tool("gcloud managed-zones list: expected JSON array".into()))?;

        let mut inv = DnsInventory {
            profile_id: profile.id.clone(),
            cloud: Cloud::Gcp,
            zones: Vec::new(),
        };

        let zone_cap = if opts.max_zones_for_records == 0 {
            zones_arr.len()
        } else {
            opts.max_zones_for_records.min(zones_arr.len())
        };

        for (i, z) in zones_arr.iter().enumerate() {
            let id = z
                .get("name")
                .or_else(|| z.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let dns_name = z
                .get("dnsName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let visibility = z
                .get("visibility")
                .and_then(|v| v.as_str())
                .unwrap_or("public");
            let private = visibility.eq_ignore_ascii_case("private");

            let mut networks = Vec::new();
            if let Some(nets) = z
                .pointer("/privateVisibilityConfig/networks")
                .and_then(|v| v.as_array())
            {
                for n in nets {
                    if let Some(url) = n.get("networkUrl").and_then(|x| x.as_str()) {
                        // URL ends with /networks/NAME
                        let short = url.rsplit('/').next().unwrap_or(url);
                        networks.push(short.to_string());
                    }
                }
            }

            let mut entry = DnsZoneEntry {
                id: id.clone(),
                name: dns_name,
                private,
                vpc_or_network_ids: networks,
                records: vec![],
                region: None,
            };

            if opts.include_records && i < zone_cap && !id.is_empty() {
                match list_rrsets(profile, &id, opts.max_records_per_zone).await {
                    Ok(recs) => entry.records = recs,
                    Err(_) => {}
                }
            }

            inv.zones.push(entry);
        }

        Ok(inv)
    }
}

async fn list_rrsets(
    profile: &Profile,
    zone_name: &str,
    max_records: usize,
) -> OscarResult<Vec<DnsRecordEntry>> {
    let mut args = vec![
        "dns".into(),
        "record-sets".into(),
        "list".into(),
        format!("--zone={zone_name}"),
        "--format=json".into(),
    ];
    args.extend(gcloud_project_args(profile));
    let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let val = run_json_command("gcloud", &a).await?;
    let arr = val.as_array().cloned().unwrap_or_default();
    let mut out = Vec::new();
    for rr in arr {
        let name = rr
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let rtype = rr
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ttl = rr.get("ttl").and_then(|v| v.as_u64()).map(|n| n as u32);
        let values = rr
            .get("rrdatas")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        out.push(DnsRecordEntry {
            name,
            record_type: rtype,
            values,
            ttl,
        });
        if max_records > 0 && out.len() >= max_records {
            break;
        }
    }
    Ok(out)
}
