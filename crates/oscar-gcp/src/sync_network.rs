//! GCP VPC networks / subnets / addresses → unified [`NetworkInventory`].

use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_identity::Profile;
use oscar_tools::inventory::{AddressEntry, NetworkInventory, SubnetEntry, VpcEntry};
use oscar_tools::sync::{gcloud_project_args, run_json_command, which_ok, NetworkInventorySource};

pub struct GcpNetworkSource;

#[async_trait]
impl NetworkInventorySource for GcpNetworkSource {
    fn cloud(&self) -> Cloud {
        Cloud::Gcp
    }

    async fn sync_network(
        &self,
        profile: &Profile,
        region: Option<&str>,
    ) -> OscarResult<NetworkInventory> {
        if !which_ok("gcloud").await {
            return Err(OscarError::Tool(
                "gcloud CLI not found on PATH — install Google Cloud SDK to sync VPC inventory"
                    .into(),
            ));
        }
        if profile.account_ref.is_empty() || profile.account_ref == "unknown" {
            return Err(OscarError::Tool(
                "GCP profile needs account_ref set to the GCP project id".into(),
            ));
        }

        let proj: Vec<String> = gcloud_project_args(profile);
        let mut net_args = vec![
            "compute".into(),
            "networks".into(),
            "list".into(),
            "--format=json".into(),
        ];
        net_args.extend(proj.clone());
        let a: Vec<&str> = net_args.iter().map(|s| s.as_str()).collect();
        let nets = run_json_command("gcloud", &a).await?;

        let mut sub_args = vec![
            "compute".into(),
            "networks".into(),
            "subnets".into(),
            "list".into(),
            "--format=json".into(),
        ];
        sub_args.extend(proj.clone());
        if let Some(r) = region {
            sub_args.push(format!("--filter=region:({r})"));
        }
        let sa: Vec<&str> = sub_args.iter().map(|s| s.as_str()).collect();
        let subnets = run_json_command("gcloud", &sa).await?;

        // Regional + global addresses (best-effort)
        let mut addr_args = vec![
            "compute".into(),
            "addresses".into(),
            "list".into(),
            "--format=json".into(),
        ];
        addr_args.extend(proj.clone());
        let aa: Vec<&str> = addr_args.iter().map(|s| s.as_str()).collect();
        let addresses = run_json_command("gcloud", &aa).await.ok();

        // Instance NICs for private IPs
        let mut inst_args = vec![
            "compute".into(),
            "instances".into(),
            "list".into(),
            "--format=json".into(),
        ];
        inst_args.extend(proj);
        let ia: Vec<&str> = inst_args.iter().map(|s| s.as_str()).collect();
        let instances = run_json_command("gcloud", &ia).await.ok();

        Ok(map_gcp_to_network_inventory(
            &profile.id,
            region.or(profile.default_region.as_deref()),
            &nets,
            &subnets,
            addresses.as_ref(),
            instances.as_ref(),
        ))
    }
}

/// Pure mapper (unit-testable).
pub fn map_gcp_to_network_inventory(
    profile_id: &str,
    region: Option<&str>,
    networks: &serde_json::Value,
    subnets: &serde_json::Value,
    addresses: Option<&serde_json::Value>,
    instances: Option<&serde_json::Value>,
) -> NetworkInventory {
    let mut vpcs = Vec::new();
    if let Some(arr) = networks.as_array() {
        for n in arr {
            let id = n
                .get("selfLink")
                .or_else(|| n.get("id"))
                .and_then(|v| v.as_str())
                .or_else(|| n.get("name").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();
            let name = n.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
            // Auto mode has no IPv4Range; use empty and rely on subnets
            let cidr = n
                .get("IPv4Range")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mut secondary = Vec::new();
            if let Some(ranges) = n.get("subnetworks").and_then(|v| v.as_array()) {
                let _ = ranges; // subnets listed separately
            }
            if let Some(peer) = n.get("peerings").and_then(|v| v.as_array()) {
                for p in peer {
                    if let Some(pn) = p.get("name").and_then(|v| v.as_str()) {
                        secondary.push(format!("peering:{pn}"));
                    }
                }
            }
            if id.is_empty() {
                continue;
            }
            vpcs.push(VpcEntry {
                id,
                name,
                cidr,
                secondary_cidrs: secondary,
                region: region.map(|s| s.to_string()),
            });
        }
    }

    let mut subnet_entries = Vec::new();
    if let Some(arr) = subnets.as_array() {
        for s in arr {
            let id = s
                .get("selfLink")
                .or_else(|| s.get("id"))
                .and_then(|v| v.as_str())
                .or_else(|| s.get("name").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();
            let name = s.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let cidr = s
                .get("ipCidrRange")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let vpc_id = s
                .get("network")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let az = s
                .get("region")
                .and_then(|v| v.as_str())
                .map(|r| r.rsplit('/').next().unwrap_or(r).to_string());
            if id.is_empty() {
                continue;
            }
            subnet_entries.push(SubnetEntry {
                id,
                name,
                cidr,
                vpc_id,
                az: az.clone(),
                region: az.or_else(|| region.map(|s| s.to_string())),
            });
        }
    }

    let mut address_entries = Vec::new();
    if let Some(arr) = addresses.and_then(|v| v.as_array()) {
        for a in arr {
            let ip = a
                .get("address")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if ip.is_empty() {
                continue;
            }
            address_entries.push(AddressEntry {
                id: a.get("selfLink").and_then(|v| v.as_str()).map(|s| s.into()),
                name: a.get("name").and_then(|v| v.as_str()).map(|s| s.into()),
                ip,
                kind: a
                    .get("addressType")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_ascii_lowercase()),
                vpc_id: a
                    .get("network")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                subnet_id: a
                    .get("subnetwork")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                region: a
                    .get("region")
                    .and_then(|v| v.as_str())
                    .map(|r| r.rsplit('/').next().unwrap_or(r).to_string())
                    .or_else(|| region.map(|s| s.to_string())),
            });
        }
    }

    if let Some(arr) = instances.and_then(|v| v.as_array()) {
        for inst in arr {
            let iname = inst.get("name").and_then(|v| v.as_str());
            if let Some(nics) = inst.get("networkInterfaces").and_then(|v| v.as_array()) {
                for nic in nics {
                    if let Some(ip) = nic.get("networkIP").and_then(|v| v.as_str()) {
                        address_entries.push(AddressEntry {
                            id: Some(format!(
                                "instance:{}/{}",
                                iname.unwrap_or("?"),
                                ip
                            )),
                            name: iname.map(|s| s.to_string()),
                            ip: ip.into(),
                            kind: Some("instance_private".into()),
                            vpc_id: nic
                                .get("network")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            subnet_id: nic
                                .get("subnetwork")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            region: region.map(|s| s.to_string()),
                        });
                    }
                    if let Some(ac) = nic.get("accessConfigs").and_then(|v| v.as_array()) {
                        for acfg in ac {
                            if let Some(nat) = acfg.get("natIP").and_then(|v| v.as_str()) {
                                address_entries.push(AddressEntry {
                                    id: Some(format!(
                                        "instance-nat:{}/{}",
                                        iname.unwrap_or("?"),
                                        nat
                                    )),
                                    name: iname.map(|s| s.to_string()),
                                    ip: nat.into(),
                                    kind: Some("instance_public".into()),
                                    vpc_id: nic
                                        .get("network")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                    subnet_id: nic
                                        .get("subnetwork")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                    region: region.map(|s| s.to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    NetworkInventory {
        profile_id: profile_id.into(),
        cloud: Cloud::Gcp,
        region: region.map(|s| s.to_string()),
        vpcs,
        subnets: subnet_entries,
        addresses: address_entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_gcp_network_and_subnet() {
        let nets = json!([{
            "name": "default",
            "selfLink": "https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
            "IPv4Range": "10.128.0.0/9"
        }]);
        let subs = json!([{
            "name": "default",
            "selfLink": "https://www.googleapis.com/compute/v1/projects/p/regions/us-central1/subnetworks/default",
            "ipCidrRange": "10.128.0.0/20",
            "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
            "region": "https://www.googleapis.com/compute/v1/projects/p/regions/us-central1"
        }]);
        let inv = map_gcp_to_network_inventory("gcp-p", Some("us-central1"), &nets, &subs, None, None);
        assert_eq!(inv.vpcs.len(), 1);
        assert_eq!(inv.subnets.len(), 1);
        assert_eq!(inv.subnets[0].cidr, "10.128.0.0/20");
        assert_eq!(inv.cloud, Cloud::Gcp);
    }
}
