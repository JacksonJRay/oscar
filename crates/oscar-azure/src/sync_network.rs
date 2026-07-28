//! Azure VNet / NSG / route tables / Functions → unified [`NetworkInventory`].

use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_identity::Profile;
use oscar_tools::inventory::{
    AddressEntry, FunctionEntry, NetworkInventory, NetworkServiceEntry, RouteEntry, RouteTableEntry,
    SecurityGroupEntry, SubnetEntry, VpcEntry,
};
use oscar_tools::sync::{run_json_command, which_ok, NetworkInventorySource};

pub struct AzureNetworkSource;

fn sub_args(profile: &Profile, base: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = base.iter().map(|s| (*s).to_string()).collect();
    if !profile.account_ref.is_empty()
        && profile.account_ref != "unknown"
        && profile.account_ref != "ambient"
    {
        args.push("--subscription".into());
        args.push(profile.account_ref.clone());
    }
    args
}

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

        let vnet_args = sub_args(profile, &["network", "vnet", "list", "-o", "json"]);
        let va: Vec<&str> = vnet_args.iter().map(|s| s.as_str()).collect();
        let vnets = run_json_command("az", &va).await?;

        let pip_args = sub_args(profile, &["network", "public-ip", "list", "-o", "json"]);
        let pa: Vec<&str> = pip_args.iter().map(|s| s.as_str()).collect();
        let pips = run_json_command("az", &pa).await.ok();

        let nic_args = sub_args(profile, &["network", "nic", "list", "-o", "json"]);
        let na: Vec<&str> = nic_args.iter().map(|s| s.as_str()).collect();
        let nics = run_json_command("az", &na).await.ok();

        let nsg_args = sub_args(profile, &["network", "nsg", "list", "-o", "json"]);
        let nsa: Vec<&str> = nsg_args.iter().map(|s| s.as_str()).collect();
        let nsgs = run_json_command("az", &nsa).await.ok();

        let rt_args = sub_args(profile, &["network", "route-table", "list", "-o", "json"]);
        let rta: Vec<&str> = rt_args.iter().map(|s| s.as_str()).collect();
        let route_tables = run_json_command("az", &rta).await.ok();

        let fn_args = sub_args(profile, &["functionapp", "list", "-o", "json"]);
        let fna: Vec<&str> = fn_args.iter().map(|s| s.as_str()).collect();
        let functions = run_json_command("az", &fna).await.ok();

        let peer_args = sub_args(
            profile,
            &["network", "vnet", "peering", "list", "--ids", ""],
        );
        // Peering is per-vnet: collect from vnet list JSON peerings property instead
        let pe_args = sub_args(profile, &["network", "private-endpoint", "list", "-o", "json"]);
        let pea: Vec<&str> = pe_args.iter().map(|s| s.as_str()).collect();
        let private_endpoints = run_json_command("az", &pea).await.ok();

        let nat_args = sub_args(profile, &["network", "nat", "gateway", "list", "-o", "json"]);
        let nata: Vec<&str> = nat_args.iter().map(|s| s.as_str()).collect();
        let nats = run_json_command("az", &nata).await.ok();

        let vgw_args = sub_args(profile, &["network", "vnet-gateway", "list", "-o", "json"]);
        let vgwa: Vec<&str> = vgw_args.iter().map(|s| s.as_str()).collect();
        let vpn_gateways = run_json_command("az", &vgwa).await.ok();

        let er_args = sub_args(profile, &["network", "express-route", "list", "-o", "json"]);
        let era: Vec<&str> = er_args.iter().map(|s| s.as_str()).collect();
        let express_routes = run_json_command("az", &era).await.ok();

        let _ = peer_args;

        Ok(map_azure_network_full(
            &profile.id,
            region.or(profile.default_region.as_deref()),
            &vnets,
            pips.as_ref(),
            nics.as_ref(),
            nsgs.as_ref(),
            route_tables.as_ref(),
            functions.as_ref(),
            private_endpoints.as_ref(),
            nats.as_ref(),
            vpn_gateways.as_ref(),
            express_routes.as_ref(),
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
    map_azure_network_full(
        profile_id,
        region,
        vnets,
        public_ips,
        nics,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn map_azure_network_full(
    profile_id: &str,
    region: Option<&str>,
    vnets: &serde_json::Value,
    public_ips: Option<&serde_json::Value>,
    nics: Option<&serde_json::Value>,
    nsgs: Option<&serde_json::Value>,
    route_tables: Option<&serde_json::Value>,
    functions: Option<&serde_json::Value>,
    private_endpoints: Option<&serde_json::Value>,
    nats: Option<&serde_json::Value>,
    vpn_gateways: Option<&serde_json::Value>,
    express_routes: Option<&serde_json::Value>,
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

    // NSG → security_groups (Azure has no separate NACLs)
    let mut security_groups = Vec::new();
    if let Some(arr) = nsgs.and_then(|v| v.as_array()) {
        for nsg in arr {
            let name = nsg
                .get("name")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let id = nsg
                .get("id")
                .and_then(|x| x.as_str())
                .or_else(|| name.as_deref())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            security_groups.push(SecurityGroupEntry {
                id,
                name,
                description: nsg
                    .get("resourceGroup")
                    .and_then(|x| x.as_str())
                    .map(|rg| format!("rg:{rg}")),
                vpc_id: None,
                region: nsg
                    .get("location")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| region.map(|s| s.to_string())),
            });
        }
    }

    let mut route_table_entries = Vec::new();
    let mut route_entries = Vec::new();
    if let Some(arr) = route_tables.and_then(|v| v.as_array()) {
        for rt in arr {
            let name = rt
                .get("name")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let id = rt
                .get("id")
                .and_then(|x| x.as_str())
                .or_else(|| name.as_deref())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            let loc = rt
                .get("location")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .or_else(|| region.map(|s| s.to_string()));
            let mut destinations = Vec::new();
            let mut targets = Vec::new();
            if let Some(routes) = rt.get("routes").and_then(|x| x.as_array()) {
                for r in routes {
                    let rname = r
                        .get("name")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    let dest = r
                        .get("addressPrefix")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    if dest.is_empty() {
                        continue;
                    }
                    let target = r
                        .get("nextHopIpAddress")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string())
                        .or_else(|| {
                            r.get("nextHopType")
                                .and_then(|x| x.as_str())
                                .map(|s| s.to_string())
                        });
                    destinations.push(dest.clone());
                    if let Some(ref t) = target {
                        targets.push(t.clone());
                    }
                    route_entries.push(RouteEntry {
                        id: format!(
                            "{}:{}",
                            id,
                            rname.as_deref().unwrap_or(dest.as_str())
                        ),
                        name: rname,
                        route_table_id: id.clone(),
                        destination: dest,
                        target,
                        vpc_id: None,
                        region: loc.clone(),
                    });
                }
            }
            destinations.sort();
            destinations.dedup();
            targets.sort();
            targets.dedup();
            route_table_entries.push(RouteTableEntry {
                id,
                name,
                vpc_id: None,
                region: loc,
                destinations,
                targets,
            });
        }
    }

    let mut function_entries = Vec::new();
    if let Some(arr) = functions.and_then(|v| v.as_array()) {
        for f in arr {
            let name = f
                .get("name")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let id = f
                .get("id")
                .and_then(|x| x.as_str())
                .or_else(|| name.as_deref())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            function_entries.push(FunctionEntry {
                id,
                name,
                runtime: f
                    .get("kind")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| {
                        f.pointer("/siteConfig/linuxFxVersion")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string())
                    }),
                region: f
                    .get("location")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| region.map(|s| s.to_string())),
                vpc_id: f
                    .pointer("/virtualNetworkSubnetId")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                arn_or_url: f
                    .get("defaultHostName")
                    .and_then(|x| x.as_str())
                    .map(|h| format!("https://{h}")),
            });
        }
    }

    let mut services = Vec::new();
    // VNet peerings nested on vnet objects
    if let Some(arr) = vnets.as_array() {
        for v in arr {
            let vpc_id = v
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let vpc_name = v.get("name").and_then(|x| x.as_str()).unwrap_or("?");
            if let Some(peers) = v
                .get("virtualNetworkPeerings")
                .or_else(|| v.get("peerings"))
                .and_then(|x| x.as_array())
            {
                for p in peers {
                    let name = p.get("name").and_then(|x| x.as_str()).map(|s| s.into());
                    let id = p
                        .get("id")
                        .and_then(|x| x.as_str())
                        .or_else(|| name.as_deref())
                        .unwrap_or("")
                        .to_string();
                    if id.is_empty() {
                        continue;
                    }
                    let remote = p
                        .pointer("/remoteVirtualNetwork/id")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    services.push(NetworkServiceEntry {
                        id,
                        name,
                        service_type: "peering".into(),
                        status: p
                            .get("peeringState")
                            .and_then(|x| x.as_str())
                            .map(|s| s.into()),
                        vpc_id: Some(if vpc_id.is_empty() {
                            vpc_name.into()
                        } else {
                            vpc_id.clone()
                        }),
                        related_ids: remote.into_iter().collect(),
                        cidrs: vec![],
                        region: v
                            .get("location")
                            .and_then(|x| x.as_str())
                            .map(|s| s.into())
                            .or_else(|| region.map(|s| s.to_string())),
                        description: Some("vnet_peering".into()),
                    });
                }
            }
        }
    }
    if let Some(arr) = private_endpoints.and_then(|v| v.as_array()) {
        for pe in arr {
            let name = pe.get("name").and_then(|x| x.as_str()).map(|s| s.into());
            let id = pe
                .get("id")
                .and_then(|x| x.as_str())
                .or_else(|| name.as_deref())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            services.push(NetworkServiceEntry {
                id,
                name,
                service_type: "private_endpoint".into(),
                status: pe
                    .get("provisioningState")
                    .and_then(|x| x.as_str())
                    .map(|s| s.into()),
                vpc_id: pe
                    .pointer("/subnet/id")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                related_ids: pe
                    .pointer("/privateLinkServiceConnections/0/privateLinkServiceId")
                    .and_then(|x| x.as_str())
                    .map(|s| vec![s.to_string()])
                    .unwrap_or_default(),
                cidrs: vec![],
                region: pe
                    .get("location")
                    .and_then(|x| x.as_str())
                    .map(|s| s.into())
                    .or_else(|| region.map(|s| s.to_string())),
                description: Some("private_endpoint".into()),
            });
        }
    }
    if let Some(arr) = nats.and_then(|v| v.as_array()) {
        for n in arr {
            let name = n.get("name").and_then(|x| x.as_str()).map(|s| s.into());
            let id = n
                .get("id")
                .and_then(|x| x.as_str())
                .or_else(|| name.as_deref())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            services.push(NetworkServiceEntry {
                id,
                name,
                service_type: "nat_gateway".into(),
                status: n
                    .get("provisioningState")
                    .and_then(|x| x.as_str())
                    .map(|s| s.into()),
                vpc_id: None,
                related_ids: vec![],
                cidrs: vec![],
                region: n
                    .get("location")
                    .and_then(|x| x.as_str())
                    .map(|s| s.into())
                    .or_else(|| region.map(|s| s.to_string())),
                description: Some("nat_gateway".into()),
            });
        }
    }
    if let Some(arr) = vpn_gateways.and_then(|v| v.as_array()) {
        for g in arr {
            let name = g.get("name").and_then(|x| x.as_str()).map(|s| s.into());
            let id = g
                .get("id")
                .and_then(|x| x.as_str())
                .or_else(|| name.as_deref())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            services.push(NetworkServiceEntry {
                id,
                name,
                service_type: "vpn".into(),
                status: g
                    .get("provisioningState")
                    .and_then(|x| x.as_str())
                    .map(|s| s.into()),
                vpc_id: g
                    .pointer("/ipConfigurations/0/subnet/id")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                related_ids: vec![],
                cidrs: vec![],
                region: g
                    .get("location")
                    .and_then(|x| x.as_str())
                    .map(|s| s.into())
                    .or_else(|| region.map(|s| s.to_string())),
                description: g
                    .get("gatewayType")
                    .and_then(|x| x.as_str())
                    .map(|s| s.into()),
            });
        }
    }
    if let Some(arr) = express_routes.and_then(|v| v.as_array()) {
        for er in arr {
            let name = er.get("name").and_then(|x| x.as_str()).map(|s| s.into());
            let id = er
                .get("id")
                .and_then(|x| x.as_str())
                .or_else(|| name.as_deref())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            services.push(NetworkServiceEntry {
                id,
                name,
                service_type: "hybrid".into(),
                status: er
                    .get("provisioningState")
                    .and_then(|x| x.as_str())
                    .map(|s| s.into()),
                vpc_id: None,
                related_ids: er
                    .get("serviceProviderName")
                    .and_then(|x| x.as_str())
                    .map(|s| vec![s.to_string()])
                    .unwrap_or_default(),
                cidrs: vec![],
                region: er
                    .get("location")
                    .and_then(|x| x.as_str())
                    .map(|s| s.into())
                    .or_else(|| region.map(|s| s.to_string())),
                description: Some("expressroute".into()),
            });
        }
    }

    NetworkInventory {
        profile_id: profile_id.into(),
        cloud: Cloud::Azure,
        region: region.map(|s| s.to_string()),
        vpcs,
        subnets,
        addresses,
        security_groups,
        nacls: vec![], // Azure uses NSGs (security_groups)
        route_tables: route_table_entries,
        routes: route_entries,
        functions: function_entries,
        services,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::{MatchMode, PatternQuery, ResourceKind};
    use oscar_tools::scan_network_inventory;
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

    #[test]
    fn maps_nsg_rt_functions() {
        let vnets = json!([]);
        let nsgs = json!([{
            "id": "/subscriptions/s/rg/providers/Microsoft.Network/networkSecurityGroups/app-nsg",
            "name": "app-nsg",
            "location": "eastus",
            "resourceGroup": "rg"
        }]);
        let rts = json!([{
            "id": "/subscriptions/s/rg/providers/Microsoft.Network/routeTables/app-rt",
            "name": "app-rt",
            "location": "eastus",
            "routes": [{
                "name": "to-onprem",
                "addressPrefix": "10.50.0.0/16",
                "nextHopType": "VirtualAppliance",
                "nextHopIpAddress": "10.0.0.4"
            }]
        }]);
        let fns = json!([{
            "id": "/subscriptions/s/rg/providers/Microsoft.Web/sites/order-fn",
            "name": "order-fn",
            "location": "eastus",
            "kind": "functionapp",
            "defaultHostName": "order-fn.azurewebsites.net"
        }]);
        let inv = map_azure_network_full(
            "az-p",
            Some("eastus"),
            &vnets,
            None,
            None,
            Some(&nsgs),
            Some(&rts),
            Some(&fns),
            None,
            None,
            None,
            None,
        );
        assert_eq!(inv.security_groups.len(), 1);
        assert_eq!(inv.route_tables.len(), 1);
        assert_eq!(inv.routes.len(), 1);
        assert_eq!(inv.functions.len(), 1);
        for (pat, kind) in [
            ("app-nsg", ResourceKind::SecurityGroup),
            ("app-rt", ResourceKind::RouteTable),
            ("10.50", ResourceKind::Route),
            ("order-fn", ResourceKind::Function),
        ] {
            let q = PatternQuery {
                pattern: pat.into(),
                mode: MatchMode::Partial,
                profile_id: None,
                region: None,
                limit: 10,
            };
            let r = scan_network_inventory(&inv, &q);
            assert!(
                r.hits.iter().any(|h| h.kind == kind),
                "pattern {pat} should hit {kind:?}"
            );
        }
    }
}
