//! GCP VPC / firewall / routes / Cloud Functions → unified [`NetworkInventory`].

use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_identity::Profile;
use oscar_tools::inventory::{
    AddressEntry, FunctionEntry, NetworkInventory, NetworkServiceEntry, RouteEntry, RouteTableEntry,
    SecurityGroupEntry, SubnetEntry, VpcEntry,
};
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
        inst_args.extend(proj.clone());
        let ia: Vec<&str> = inst_args.iter().map(|s| s.as_str()).collect();
        let instances = run_json_command("gcloud", &ia).await.ok();

        // Firewall rules ≈ security groups
        let mut fw_args = vec![
            "compute".into(),
            "firewall-rules".into(),
            "list".into(),
            "--format=json".into(),
        ];
        fw_args.extend(proj.clone());
        let fa: Vec<&str> = fw_args.iter().map(|s| s.as_str()).collect();
        let firewalls = run_json_command("gcloud", &fa).await.ok();

        // VPC routes
        let mut rt_args = vec![
            "compute".into(),
            "routes".into(),
            "list".into(),
            "--format=json".into(),
        ];
        rt_args.extend(proj.clone());
        let ra: Vec<&str> = rt_args.iter().map(|s| s.as_str()).collect();
        let routes = run_json_command("gcloud", &ra).await.ok();

        // Cloud Functions (gen1 + gen2 via functions list)
        let mut fn_args = vec![
            "functions".into(),
            "list".into(),
            "--format=json".into(),
        ];
        fn_args.extend(proj.clone());
        if let Some(r) = region {
            fn_args.push(format!("--regions={r}"));
        }
        let fna: Vec<&str> = fn_args.iter().map(|s| s.as_str()).collect();
        let functions = run_json_command("gcloud", &fna).await.ok();

        // Cloud Run services (often used as "cloud functions" gen2 backend) — best effort
        let mut cr_args = vec![
            "run".into(),
            "services".into(),
            "list".into(),
            "--format=json".into(),
            "--platform=managed".into(),
        ];
        cr_args.extend(proj.clone());
        if let Some(r) = region {
            cr_args.push(format!("--region={r}"));
        }
        let cra: Vec<&str> = cr_args.iter().map(|s| s.as_str()).collect();
        let cloud_run = run_json_command("gcloud", &cra).await.ok();

        // Connectivity fabric (best-effort)
        let mut vpn_args = vec![
            "compute".into(),
            "vpn-tunnels".into(),
            "list".into(),
            "--format=json".into(),
        ];
        vpn_args.extend(proj.clone());
        let vpn_refs: Vec<&str> = vpn_args.iter().map(|s| s.as_str()).collect();
        let vpn_tunnels = run_json_command("gcloud", &vpn_refs).await.ok();

        let mut ic_args = vec![
            "compute".into(),
            "interconnects".into(),
            "list".into(),
            "--format=json".into(),
        ];
        ic_args.extend(proj.clone());
        let ic_refs: Vec<&str> = ic_args.iter().map(|s| s.as_str()).collect();
        let interconnects = run_json_command("gcloud", &ic_refs).await.ok();

        let mut router_args = vec![
            "compute".into(),
            "routers".into(),
            "list".into(),
            "--format=json".into(),
        ];
        router_args.extend(proj.clone());
        let router_refs: Vec<&str> = router_args.iter().map(|s| s.as_str()).collect();
        let routers = run_json_command("gcloud", &router_refs).await.ok();

        let shared = run_json_command(
            "gcloud",
            &[
                "compute",
                "shared-vpc",
                "list-associated-resources",
                &profile.account_ref,
                "--format=json",
            ],
        )
        .await
        .ok();

        Ok(map_gcp_network_full(
            &profile.id,
            region.or(profile.default_region.as_deref()),
            &nets,
            &subnets,
            addresses.as_ref(),
            instances.as_ref(),
            firewalls.as_ref(),
            routes.as_ref(),
            functions.as_ref(),
            cloud_run.as_ref(),
            vpn_tunnels.as_ref(),
            interconnects.as_ref(),
            routers.as_ref(),
            shared.as_ref(),
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
    map_gcp_network_full(
        profile_id,
        region,
        networks,
        subnets,
        addresses,
        instances,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

/// Full mapper including firewalls, routes, Cloud Functions / Cloud Run / fabric services.
#[allow(clippy::too_many_arguments)]
pub fn map_gcp_network_full(
    profile_id: &str,
    region: Option<&str>,
    networks: &serde_json::Value,
    subnets: &serde_json::Value,
    addresses: Option<&serde_json::Value>,
    instances: Option<&serde_json::Value>,
    firewalls: Option<&serde_json::Value>,
    routes_json: Option<&serde_json::Value>,
    functions: Option<&serde_json::Value>,
    cloud_run: Option<&serde_json::Value>,
    vpn_tunnels: Option<&serde_json::Value>,
    interconnects: Option<&serde_json::Value>,
    routers: Option<&serde_json::Value>,
    shared_vpc: Option<&serde_json::Value>,
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

    // Firewall rules → security_groups (GCP has no separate NACLs)
    let mut security_groups = Vec::new();
    if let Some(arr) = firewalls.and_then(|v| v.as_array()) {
        for fw in arr {
            let name = fw.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let id = fw
                .get("selfLink")
                .or_else(|| fw.get("id"))
                .and_then(|v| v.as_str())
                .or_else(|| name.as_deref())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            security_groups.push(SecurityGroupEntry {
                id,
                name,
                description: fw
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                vpc_id: fw
                    .get("network")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                region: region.map(|s| s.to_string()),
            });
        }
    }

    // Routes → route entries + synthetic global route table
    let mut route_entries = Vec::new();
    let mut destinations = Vec::new();
    let mut targets = Vec::new();
    if let Some(arr) = routes_json.and_then(|v| v.as_array()) {
        for r in arr {
            let name = r.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let id = r
                .get("selfLink")
                .or_else(|| r.get("id"))
                .and_then(|v| v.as_str())
                .or_else(|| name.as_deref())
                .unwrap_or("")
                .to_string();
            let dest = r
                .get("destRange")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if id.is_empty() && dest.is_empty() {
                continue;
            }
            let target = r
                .get("nextHopGateway")
                .or_else(|| r.get("nextHopIp"))
                .or_else(|| r.get("nextHopInstance"))
                .or_else(|| r.get("nextHopVpnTunnel"))
                .or_else(|| r.get("nextHopIlb"))
                .or_else(|| r.get("nextHopPeering"))
                .or_else(|| r.get("nextHopNetwork"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if !dest.is_empty() {
                destinations.push(dest.clone());
            }
            if let Some(ref t) = target {
                targets.push(t.clone());
            }
            let vpc_id = r
                .get("network")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            route_entries.push(RouteEntry {
                id: if id.is_empty() {
                    format!("route:{dest}")
                } else {
                    id
                },
                name,
                route_table_id: "gcp-global-routes".into(),
                destination: dest,
                target,
                vpc_id,
                region: region.map(|s| s.to_string()),
            });
        }
    }
    destinations.sort();
    destinations.dedup();
    targets.sort();
    targets.dedup();
    let route_tables = if route_entries.is_empty() {
        vec![]
    } else {
        vec![RouteTableEntry {
            id: "gcp-global-routes".into(),
            name: Some("global".into()),
            vpc_id: None,
            region: region.map(|s| s.to_string()),
            destinations,
            targets,
        }]
    };

    let mut function_entries = Vec::new();
    if let Some(arr) = functions.and_then(|v| v.as_array()) {
        for f in arr {
            let name = f
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.rsplit('/').next().unwrap_or(s).to_string());
            let id = f
                .get("name")
                .or_else(|| f.get("buildConfig").and_then(|b| b.get("build")))
                .and_then(|v| v.as_str())
                .or_else(|| name.as_deref())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            let runtime = f
                .get("runtime")
                .or_else(|| f.pointer("/buildConfig/runtime"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let region_f = f
                .get("region")
                .and_then(|v| v.as_str())
                .map(|s| s.rsplit('/').next().unwrap_or(s).to_string())
                .or_else(|| {
                    // name like projects/p/locations/us-central1/functions/fn
                    f.get("name").and_then(|v| v.as_str()).and_then(|n| {
                        let parts: Vec<&str> = n.split('/').collect();
                        parts
                            .windows(2)
                            .find(|w| w[0] == "locations")
                            .map(|w| w[1].to_string())
                    })
                })
                .or_else(|| region.map(|s| s.to_string()));
            function_entries.push(FunctionEntry {
                id,
                name,
                runtime,
                region: region_f,
                vpc_id: f
                    .pointer("/serviceConfig/vpcConnector")
                    .or_else(|| f.get("vpcConnector"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                arn_or_url: f
                    .get("url")
                    .or_else(|| f.pointer("/serviceConfig/uri"))
                    .or_else(|| f.get("httpsTrigger").and_then(|h| h.get("url")))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            });
        }
    }
    if let Some(arr) = cloud_run.and_then(|v| v.as_array()) {
        for svc in arr {
            let meta = svc.get("metadata");
            let name = meta
                .and_then(|m| m.get("name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let id = meta
                .and_then(|m| m.get("selfLink"))
                .and_then(|v| v.as_str())
                .or_else(|| name.as_deref())
                .or_else(|| {
                    svc.get("status")
                        .and_then(|s| s.get("url"))
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("")
                .to_string();
            if id.is_empty() && name.is_none() {
                continue;
            }
            // Avoid dup if already listed as Cloud Function
            if function_entries.iter().any(|f| {
                f.name.as_deref() == name.as_deref() || f.id == id
            }) {
                continue;
            }
            function_entries.push(FunctionEntry {
                id: if id.is_empty() {
                    name.clone().unwrap_or_else(|| "cloud-run".into())
                } else {
                    id
                },
                name,
                runtime: Some("cloud-run".into()),
                region: meta
                    .and_then(|m| m.get("labels"))
                    .and_then(|l| l.get("cloud.googleapis.com/location"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| region.map(|s| s.to_string())),
                vpc_id: None,
                arn_or_url: svc
                    .pointer("/status/url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            });
        }
    }

    let mut services = Vec::new();
    // VPC network peerings embedded on networks
    if let Some(arr) = networks.as_array() {
        for n in arr {
            let net_name = n.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let net_id = n
                .get("selfLink")
                .and_then(|v| v.as_str())
                .unwrap_or(net_name);
            if let Some(peer) = n.get("peerings").and_then(|v| v.as_array()) {
                for p in peer {
                    let pname = p.get("name").and_then(|v| v.as_str()).unwrap_or("peering");
                    let state = p.get("state").and_then(|v| v.as_str()).map(|s| s.into());
                    let network = p
                        .get("network")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    services.push(NetworkServiceEntry {
                        id: format!("{net_id}/peerings/{pname}"),
                        name: Some(pname.into()),
                        service_type: "peering".into(),
                        status: state,
                        vpc_id: Some(net_id.into()),
                        related_ids: network.into_iter().collect(),
                        cidrs: vec![],
                        region: region.map(|s| s.to_string()),
                        description: Some("vpc_network_peering".into()),
                    });
                }
            }
        }
    }
    if let Some(arr) = vpn_tunnels.and_then(|v| v.as_array()) {
        for t in arr {
            let name = t.get("name").and_then(|v| v.as_str()).map(|s| s.into());
            let id = t
                .get("selfLink")
                .or_else(|| t.get("id"))
                .and_then(|v| v.as_str())
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
                status: t.get("status").and_then(|v| v.as_str()).map(|s| s.into()),
                vpc_id: t
                    .get("network")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                related_ids: t
                    .get("peerIp")
                    .and_then(|v| v.as_str())
                    .map(|s| vec![s.to_string()])
                    .unwrap_or_default(),
                cidrs: vec![],
                region: t
                    .get("region")
                    .and_then(|v| v.as_str())
                    .map(|r| r.rsplit('/').next().unwrap_or(r).to_string())
                    .or_else(|| region.map(|s| s.to_string())),
                description: Some("vpn_tunnel".into()),
            });
        }
    }
    if let Some(arr) = interconnects.and_then(|v| v.as_array()) {
        for ic in arr {
            let name = ic.get("name").and_then(|v| v.as_str()).map(|s| s.into());
            let id = ic
                .get("selfLink")
                .or_else(|| ic.get("id"))
                .and_then(|v| v.as_str())
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
                status: ic
                    .get("operationalStatus")
                    .or_else(|| ic.get("state"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.into()),
                vpc_id: None,
                related_ids: vec![],
                cidrs: vec![],
                region: region.map(|s| s.to_string()),
                description: Some("interconnect".into()),
            });
        }
    }
    // Cloud Router + NAT
    if let Some(arr) = routers.and_then(|v| v.as_array()) {
        for r in arr {
            let rname = r.get("name").and_then(|v| v.as_str()).unwrap_or("router");
            let rid = r
                .get("selfLink")
                .and_then(|v| v.as_str())
                .unwrap_or(rname);
            if let Some(nats) = r.get("nats").and_then(|v| v.as_array()) {
                for n in nats {
                    let nname = n.get("name").and_then(|v| v.as_str()).unwrap_or("nat");
                    services.push(NetworkServiceEntry {
                        id: format!("{rid}/nats/{nname}"),
                        name: Some(nname.into()),
                        service_type: "nat_gateway".into(),
                        status: None,
                        vpc_id: r
                            .get("network")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        related_ids: vec![rname.to_string()],
                        cidrs: vec![],
                        region: r
                            .get("region")
                            .and_then(|v| v.as_str())
                            .map(|x| x.rsplit('/').next().unwrap_or(x).to_string())
                            .or_else(|| region.map(|s| s.to_string())),
                        description: Some("cloud_nat".into()),
                    });
                }
            }
        }
    }
    if let Some(arr) = shared_vpc.and_then(|v| v.as_array()) {
        for s in arr {
            let id = s
                .get("id")
                .or_else(|| s.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("shared-vpc")
                .to_string();
            services.push(NetworkServiceEntry {
                id: id.clone(),
                name: Some(id),
                service_type: "network_share".into(),
                status: None,
                vpc_id: None,
                related_ids: vec![],
                cidrs: vec![],
                region: region.map(|s| s.to_string()),
                description: Some("shared_vpc".into()),
            });
        }
    } else if let Some(obj) = shared_vpc.and_then(|v| v.as_object()) {
        // single host project object
        if let Some(name) = obj.get("name").and_then(|v| v.as_str()) {
            services.push(NetworkServiceEntry {
                id: name.into(),
                name: Some(name.into()),
                service_type: "network_share".into(),
                status: None,
                vpc_id: None,
                related_ids: vec![],
                cidrs: vec![],
                region: region.map(|s| s.to_string()),
                description: Some("shared_vpc_host".into()),
            });
        }
    }

    NetworkInventory {
        profile_id: profile_id.into(),
        cloud: Cloud::Gcp,
        region: region.map(|s| s.to_string()),
        vpcs,
        subnets: subnet_entries,
        addresses: address_entries,
        security_groups,
        nacls: vec![], // GCP uses firewall rules (security_groups), not NACLs
        route_tables,
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

    #[test]
    fn maps_firewall_routes_functions() {
        let nets = json!([{"name": "default", "selfLink": "net/default"}]);
        let subs = json!([]);
        let fws = json!([{
            "name": "allow-ssh",
            "selfLink": "fw/allow-ssh",
            "description": "ssh",
            "network": "net/default"
        }]);
        let rts = json!([{
            "name": "default-route",
            "selfLink": "routes/default-route",
            "destRange": "0.0.0.0/0",
            "nextHopGateway": "global/gateways/default-internet-gateway",
            "network": "net/default"
        }]);
        let fns = json!([{
            "name": "projects/p/locations/us-central1/functions/hello-http",
            "runtime": "python312",
            "httpsTrigger": {"url": "https://us-central1-p.cloudfunctions.net/hello-http"}
        }]);
        let inv = map_gcp_network_full(
            "gcp-p",
            Some("us-central1"),
            &nets,
            &subs,
            None,
            None,
            Some(&fws),
            Some(&rts),
            Some(&fns),
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(inv.security_groups.len(), 1);
        assert_eq!(inv.routes.len(), 1);
        assert_eq!(inv.functions.len(), 1);
        let q = PatternQuery {
            pattern: "allow-ssh".into(),
            mode: MatchMode::Partial,
            profile_id: None,
            region: None,
            limit: 10,
        };
        let r = scan_network_inventory(&inv, &q);
        assert!(r.hits.iter().any(|h| h.kind == ResourceKind::SecurityGroup));
        let q2 = PatternQuery {
            pattern: "hello-http".into(),
            mode: MatchMode::Partial,
            profile_id: None,
            region: None,
            limit: 10,
        };
        let r2 = scan_network_inventory(&inv, &q2);
        assert!(r2.hits.iter().any(|h| h.kind == ResourceKind::Function));
    }
}
