//! Azure VNet / subnet / public IP / NIC → unified [`NetworkInventory`].

use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_identity::Profile;
use oscar_tools::inventory::{AddressEntry, NetworkInventory, SubnetEntry, VpcEntry};
use oscar_tools::sync::{run_json_command, which_ok, NetworkInventorySource};

pub struct AzureNetworkSource;

#[async_trait]
impl NetworkInventorySource for AzureNetworkSource {
    fn cloud(&self) -> Cloud {
        Cloud::Azure
    }

    async fn sync_network(
        &self,
        profile: &Profile,
        region: Option<&str>,
    ) -> OscarResult<NetworkInventory> {
        if !which_ok("az").await {
            return Err(OscarError::Tool(
                "az CLI not found on PATH — install Azure CLI to sync VNet inventory".into(),
            ));
        }

        let mut vnet_args = vec![
            "network".into(),
            "vnet".into(),
            "list".into(),
            "-o".into(),
            "json".into(),
        ];
        // Optional subscription from account_ref
        if !profile.account_ref.is_empty()
            && profile.account_ref != "unknown"
            && profile.account_ref != "ambient"
        {
            vnet_args.push("--subscription".into());
            vnet_args.push(profile.account_ref.clone());
        }
        let va: Vec<&str> = vnet_args.iter().map(|s| s.as_str()).collect();
        let vnets = run_json_command("az", &va).await?;

        let mut pip_args = vec![
            "network".into(),
            "public-ip".into(),
            "list".into(),
            "-o".into(),
            "json".into(),
        ];
        if !profile.account_ref.is_empty()
            && profile.account_ref != "unknown"
            && profile.account_ref != "ambient"
        {
            pip_args.push("--subscription".into());
            pip_args.push(profile.account_ref.clone());
        }
        let pa: Vec<&str> = pip_args.iter().map(|s| s.as_str()).collect();
        let pips = run_json_command("az", &pa).await.ok();

        let mut nic_args = vec![
            "network".into(),
            "nic".into(),
            "list".into(),
            "-o".into(),
            "json".into(),
        ];
        if !profile.account_ref.is_empty()
            && profile.account_ref != "unknown"
            && profile.account_ref != "ambient"
        {
            nic_args.push("--subscription".into());
            nic_args.push(profile.account_ref.clone());
        }
        let na: Vec<&str> = nic_args.iter().map(|s| s.as_str()).collect();
        let nics = run_json_command("az", &na).await.ok();

        Ok(map_azure_to_network_inventory(
            &profile.id,
            region.or(profile.default_region.as_deref()),
            &vnets,
            pips.as_ref(),
            nics.as_ref(),
        ))
    }
}

pub fn map_azure_to_network_inventory(
    profile_id: &str,
    region: Option<&str>,
    vnets: &serde_json::Value,
    public_ips: Option<&serde_json::Value>,
    nics: Option<&serde_json::Value>,
) -> NetworkInventory {
    let mut vpcs = Vec::new();
    let mut subnets = Vec::new();

    if let Some(arr) = vnets.as_array() {
        for v in arr {
            let id = v
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let name = v
                .get("name")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let loc = v
                .get("location")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .or_else(|| region.map(|s| s.to_string()));
            // addressSpace.addressPrefixes
            let mut cidrs: Vec<String> = v
                .pointer("/addressSpace/addressPrefixes")
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|p| p.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let primary = cidrs.first().cloned().unwrap_or_default();
            let secondary: Vec<String> = if cidrs.len() > 1 {
                cidrs.split_off(1)
            } else {
                vec![]
            };
            if id.is_empty() && name.is_none() {
                continue;
            }
            let vpc_id = if id.is_empty() {
                name.clone().unwrap_or_else(|| "vnet".into())
            } else {
                id.clone()
            };
            vpcs.push(VpcEntry {
                id: vpc_id.clone(),
                name: name.clone(),
                cidr: primary,
                secondary_cidrs: secondary,
                region: loc.clone(),
            });

            // subnets embedded on vnet
            if let Some(subs) = v.get("subnets").and_then(|x| x.as_array()) {
                for s in subs {
                    let sid = s
                        .get("id")
                        .and_then(|x| x.as_str())
                        .or_else(|| s.get("name").and_then(|x| x.as_str()))
                        .unwrap_or("")
                        .to_string();
                    let sname = s.get("name").and_then(|x| x.as_str()).map(|s| s.to_string());
                    let scidr = s
                        .get("addressPrefix")
                        .and_then(|x| x.as_str())
                        .or_else(|| {
                            s.pointer("/addressPrefixes/0")
                                .and_then(|x| x.as_str())
                        })
                        .unwrap_or("")
                        .to_string();
                    if sid.is_empty() {
                        continue;
                    }
                    subnets.push(SubnetEntry {
                        id: sid,
                        name: sname,
                        cidr: scidr,
                        vpc_id: vpc_id.clone(),
                        az: None,
                        region: loc.clone(),
                    });
                }
            }
        }
    }

    let mut addresses = Vec::new();
    if let Some(arr) = public_ips.and_then(|v| v.as_array()) {
        for p in arr {
            let ip = p
                .get("ipAddress")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if ip.is_empty() {
                continue;
            }
            addresses.push(AddressEntry {
                id: p.get("id").and_then(|x| x.as_str()).map(|s| s.into()),
                name: p.get("name").and_then(|x| x.as_str()).map(|s| s.into()),
                ip,
                kind: Some("public_ip".into()),
                vpc_id: None,
                subnet_id: None,
                region: p
                    .get("location")
                    .and_then(|x| x.as_str())
                    .map(|s| s.into())
                    .or_else(|| region.map(|s| s.to_string())),
            });
        }
    }

    if let Some(arr) = nics.and_then(|v| v.as_array()) {
        for nic in arr {
            let nic_name = nic.get("name").and_then(|x| x.as_str());
            if let Some(ipcfgs) = nic.get("ipConfigurations").and_then(|x| x.as_array()) {
                for cfg in ipcfgs {
                    let private = cfg
                        .get("privateIPAddress")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    if private.is_empty() {
                        continue;
                    }
                    let subnet = cfg
                        .pointer("/subnet/id")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    addresses.push(AddressEntry {
                        id: cfg.get("id").and_then(|x| x.as_str()).map(|s| s.into()),
                        name: nic_name.map(|s| s.to_string()),
                        ip: private.into(),
                        kind: Some("nic_private".into()),
                        vpc_id: None,
                        subnet_id: subnet,
                        region: nic
                            .get("location")
                            .and_then(|x| x.as_str())
                            .map(|s| s.into())
                            .or_else(|| region.map(|s| s.to_string())),
                    });
                }
            }
        }
    }

    NetworkInventory {
        profile_id: profile_id.into(),
        cloud: Cloud::Azure,
        region: region.map(|s| s.to_string()),
        vpcs,
        subnets,
        addresses,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_vnet_with_subnet() {
        let vnets = json!([{
            "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1",
            "name": "vnet1",
            "location": "eastus",
            "addressSpace": { "addressPrefixes": ["10.0.0.0/16"] },
            "subnets": [{
                "id": "/subscriptions/s/.../subnets/default",
                "name": "default",
                "addressPrefix": "10.0.1.0/24"
            }]
        }]);
        let inv = map_azure_to_network_inventory("az-p", Some("eastus"), &vnets, None, None);
        assert_eq!(inv.vpcs.len(), 1);
        assert_eq!(inv.subnets.len(), 1);
        assert_eq!(inv.subnets[0].cidr, "10.0.1.0/24");
        assert_eq!(inv.cloud, Cloud::Azure);
    }
}
