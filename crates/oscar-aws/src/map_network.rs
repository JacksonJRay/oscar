//! Pure AWS EC2/Lambda JSON → unified [`NetworkInventory`] (no CLI / network I/O).
//!
//! Tests and live sync both call this so the agent-facing shape stays stable.

use oscar_core::Cloud;
use oscar_tools::inventory::{
    AddressEntry, FunctionEntry, NaclEntry, NetworkInventory, NetworkServiceEntry, RouteEntry,
    RouteTableEntry, SecurityGroupEntry, SubnetEntry, VpcEntry,
};
use serde_json::Value;

/// Build unified network inventory from AWS CLI JSON blobs.
///
/// Expected shapes match `aws ec2 describe-vpcs|describe-subnets|describe-network-interfaces
/// |describe-addresses|describe-security-groups|describe-network-acls|describe-route-tables`
/// and `aws lambda list-functions --output json`.
pub fn map_aws_ec2_to_network_inventory(
    profile_id: impl Into<String>,
    region: Option<String>,
    vpcs_json: &Value,
    subnets_json: &Value,
    enis_json: Option<&Value>,
    eips_json: Option<&Value>,
) -> NetworkInventory {
    map_aws_to_network_inventory(
        profile_id,
        region,
        vpcs_json,
        subnets_json,
        enis_json,
        eips_json,
        None,
        None,
        None,
        None,
    )
}

/// Full mapper including SG / NACL / route tables / Lambda / peering / TGW / VPN / endpoints / NAT.
pub fn map_aws_to_network_inventory(
    profile_id: impl Into<String>,
    region: Option<String>,
    vpcs_json: &Value,
    subnets_json: &Value,
    enis_json: Option<&Value>,
    eips_json: Option<&Value>,
    sgs_json: Option<&Value>,
    nacls_json: Option<&Value>,
    rts_json: Option<&Value>,
    functions_json: Option<&Value>,
) -> NetworkInventory {
    map_aws_network_full(
        profile_id,
        region,
        vpcs_json,
        subnets_json,
        enis_json,
        eips_json,
        sgs_json,
        nacls_json,
        rts_json,
        functions_json,
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

/// Full AWS network inventory including connectivity fabric services.
#[allow(clippy::too_many_arguments)]
pub fn map_aws_network_full(
    profile_id: impl Into<String>,
    region: Option<String>,
    vpcs_json: &Value,
    subnets_json: &Value,
    enis_json: Option<&Value>,
    eips_json: Option<&Value>,
    sgs_json: Option<&Value>,
    nacls_json: Option<&Value>,
    rts_json: Option<&Value>,
    functions_json: Option<&Value>,
    peerings_json: Option<&Value>,
    tgw_json: Option<&Value>,
    vpn_json: Option<&Value>,
    endpoints_json: Option<&Value>,
    nats_json: Option<&Value>,
    igws_json: Option<&Value>,
    prefix_lists_json: Option<&Value>,
    dx_json: Option<&Value>,
) -> NetworkInventory {
    let profile_id = profile_id.into();
    let region_ref = region.clone();
    let region_s = region_ref.as_deref();

    let vpcs = parse_vpcs(vpcs_json, region_s);
    let subnets = parse_subnets(subnets_json, region_s);
    let mut addresses = Vec::new();
    if let Some(enis) = enis_json {
        addresses.extend(parse_eni_addresses(enis, region_s));
    }
    if let Some(eips) = eips_json {
        addresses.extend(parse_elastic_ips(eips, region_s));
    }
    let security_groups = sgs_json
        .map(|j| parse_security_groups(j, region_s))
        .unwrap_or_default();
    let nacls = nacls_json
        .map(|j| parse_nacls(j, region_s))
        .unwrap_or_default();
    let (route_tables, routes) = rts_json
        .map(|j| parse_route_tables(j, region_s))
        .unwrap_or_default();
    let functions = functions_json
        .map(|j| parse_lambda_functions(j, region_s))
        .unwrap_or_default();

    let mut services = Vec::new();
    if let Some(j) = peerings_json {
        services.extend(parse_vpc_peerings(j, region_s));
    }
    if let Some(j) = tgw_json {
        services.extend(parse_transit_gateways(j, region_s));
    }
    if let Some(j) = vpn_json {
        services.extend(parse_vpn_connections(j, region_s));
    }
    if let Some(j) = endpoints_json {
        services.extend(parse_vpc_endpoints(j, region_s));
    }
    if let Some(j) = nats_json {
        services.extend(parse_nat_gateways(j, region_s));
    }
    if let Some(j) = igws_json {
        services.extend(parse_internet_gateways(j, region_s));
    }
    if let Some(j) = prefix_lists_json {
        services.extend(parse_prefix_lists(j, region_s));
    }
    if let Some(j) = dx_json {
        services.extend(parse_dx_connections(j, region_s));
    }

    NetworkInventory {
        profile_id,
        cloud: Cloud::Aws,
        region,
        vpcs,
        subnets,
        addresses,
        security_groups,
        nacls,
        route_tables,
        routes,
        functions,
        services,
    }
}

fn tag_name(tags: Option<&Value>) -> Option<String> {
    let arr = tags?.as_array()?;
    for t in arr {
        let key = t.get("Key").and_then(|k| k.as_str())?;
        if key.eq_ignore_ascii_case("Name") {
            return t
                .get("Value")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
        }
    }
    None
}

fn parse_vpcs(json: &Value, region: Option<&str>) -> Vec<VpcEntry> {
    let mut out = Vec::new();
    let Some(arr) = json.get("Vpcs").and_then(|v| v.as_array()) else {
        return out;
    };
    for v in arr {
        let id = v
            .get("VpcId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let cidr = v
            .get("CidrBlock")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let mut secondary = Vec::new();
        if let Some(assoc) = v.get("CidrBlockAssociationSet").and_then(|a| a.as_array()) {
            for a in assoc {
                if let Some(c) = a.get("CidrBlock").and_then(|x| x.as_str()) {
                    if c != cidr {
                        secondary.push(c.to_string());
                    }
                }
            }
        }
        out.push(VpcEntry {
            id,
            name: tag_name(v.get("Tags")),
            cidr,
            secondary_cidrs: secondary,
            region: region.map(|s| s.to_string()),
        });
    }
    out
}

fn parse_subnets(json: &Value, region: Option<&str>) -> Vec<SubnetEntry> {
    let mut out = Vec::new();
    let Some(arr) = json.get("Subnets").and_then(|v| v.as_array()) else {
        return out;
    };
    for s in arr {
        let id = s
            .get("SubnetId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        out.push(SubnetEntry {
            id,
            name: tag_name(s.get("Tags")),
            cidr: s
                .get("CidrBlock")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            vpc_id: s
                .get("VpcId")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            az: s
                .get("AvailabilityZone")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            region: region.map(|s| s.to_string()),
        });
    }
    out
}

fn parse_eni_addresses(json: &Value, region: Option<&str>) -> Vec<AddressEntry> {
    let mut out = Vec::new();
    let Some(arr) = json
        .get("NetworkInterfaces")
        .and_then(|v| v.as_array())
    else {
        return out;
    };
    for eni in arr {
        let eni_id = eni
            .get("NetworkInterfaceId")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let vpc_id = eni
            .get("VpcId")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let subnet_id = eni
            .get("SubnetId")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let name = tag_name(eni.get("TagSet")).or_else(|| tag_name(eni.get("Tags")));
        // Private IPs
        if let Some(privates) = eni
            .get("PrivateIpAddresses")
            .and_then(|v| v.as_array())
        {
            for p in privates {
                if let Some(ip) = p.get("PrivateIpAddress").and_then(|x| x.as_str()) {
                    out.push(AddressEntry {
                        id: eni_id.clone(),
                        name: name.clone(),
                        ip: ip.to_string(),
                        kind: Some("eni-private".into()),
                        vpc_id: vpc_id.clone(),
                        subnet_id: subnet_id.clone(),
                        region: region.map(|s| s.to_string()),
                    });
                }
                if let Some(assoc) = p.get("Association") {
                    if let Some(pub_ip) = assoc.get("PublicIp").and_then(|x| x.as_str()) {
                        out.push(AddressEntry {
                            id: eni_id.clone(),
                            name: name.clone(),
                            ip: pub_ip.to_string(),
                            kind: Some("eni-public".into()),
                            vpc_id: vpc_id.clone(),
                            subnet_id: subnet_id.clone(),
                            region: region.map(|s| s.to_string()),
                        });
                    }
                }
            }
        } else if let Some(ip) = eni.get("PrivateIpAddress").and_then(|x| x.as_str()) {
            out.push(AddressEntry {
                id: eni_id,
                name,
                ip: ip.to_string(),
                kind: Some("eni-private".into()),
                vpc_id,
                subnet_id,
                region: region.map(|s| s.to_string()),
            });
        }
    }
    out
}

fn parse_elastic_ips(json: &Value, region: Option<&str>) -> Vec<AddressEntry> {
    let mut out = Vec::new();
    let Some(arr) = json.get("Addresses").and_then(|v| v.as_array()) else {
        return out;
    };
    for a in arr {
        let public = a.get("PublicIp").and_then(|x| x.as_str());
        let private = a.get("PrivateIpAddress").and_then(|x| x.as_str());
        let alloc = a
            .get("AllocationId")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let name = tag_name(a.get("Tags"));
        if let Some(ip) = public {
            out.push(AddressEntry {
                id: alloc.clone(),
                name: name.clone(),
                ip: ip.to_string(),
                kind: Some("eip".into()),
                vpc_id: None,
                subnet_id: None,
                region: region.map(|s| s.to_string()),
            });
        }
        if let Some(ip) = private {
            out.push(AddressEntry {
                id: alloc,
                name,
                ip: ip.to_string(),
                kind: Some("eip-private".into()),
                vpc_id: None,
                subnet_id: None,
                region: region.map(|s| s.to_string()),
            });
        }
    }
    out
}

fn parse_security_groups(json: &Value, region: Option<&str>) -> Vec<SecurityGroupEntry> {
    let mut out = Vec::new();
    let Some(arr) = json.get("SecurityGroups").and_then(|v| v.as_array()) else {
        return out;
    };
    for sg in arr {
        let id = sg
            .get("GroupId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let name = sg
            .get("GroupName")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .or_else(|| tag_name(sg.get("Tags")));
        out.push(SecurityGroupEntry {
            id,
            name,
            description: sg
                .get("Description")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            vpc_id: sg
                .get("VpcId")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            region: region.map(|s| s.to_string()),
        });
    }
    out
}

fn parse_nacls(json: &Value, region: Option<&str>) -> Vec<NaclEntry> {
    let mut out = Vec::new();
    let Some(arr) = json.get("NetworkAcls").and_then(|v| v.as_array()) else {
        return out;
    };
    for n in arr {
        let id = n
            .get("NetworkAclId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        out.push(NaclEntry {
            id,
            name: tag_name(n.get("Tags")),
            vpc_id: n
                .get("VpcId")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            is_default: n.get("IsDefault").and_then(|x| x.as_bool()),
            region: region.map(|s| s.to_string()),
        });
    }
    out
}

fn parse_route_tables(
    json: &Value,
    region: Option<&str>,
) -> (Vec<RouteTableEntry>, Vec<RouteEntry>) {
    let mut tables = Vec::new();
    let mut routes = Vec::new();
    let Some(arr) = json.get("RouteTables").and_then(|v| v.as_array()) else {
        return (tables, routes);
    };
    for rt in arr {
        let id = rt
            .get("RouteTableId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let vpc_id = rt
            .get("VpcId")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let name = tag_name(rt.get("Tags"));
        let mut destinations = Vec::new();
        let mut targets = Vec::new();
        if let Some(rs) = rt.get("Routes").and_then(|v| v.as_array()) {
            for r in rs {
                let dest = r
                    .get("DestinationCidrBlock")
                    .or_else(|| r.get("DestinationIpv6CidrBlock"))
                    .or_else(|| r.get("DestinationPrefixListId"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                if dest.is_empty() {
                    continue;
                }
                let target = route_target(r);
                destinations.push(dest.clone());
                if let Some(ref t) = target {
                    targets.push(t.clone());
                }
                routes.push(RouteEntry {
                    id: format!("{id}:{dest}"),
                    name: name.clone(),
                    route_table_id: id.clone(),
                    destination: dest,
                    target,
                    vpc_id: vpc_id.clone(),
                    region: region.map(|s| s.to_string()),
                });
            }
        }
        destinations.sort();
        destinations.dedup();
        targets.sort();
        targets.dedup();
        tables.push(RouteTableEntry {
            id,
            name,
            vpc_id,
            region: region.map(|s| s.to_string()),
            destinations,
            targets,
        });
    }
    (tables, routes)
}

fn route_target(r: &Value) -> Option<String> {
    const KEYS: &[&str] = &[
        "GatewayId",
        "NatGatewayId",
        "TransitGatewayId",
        "VpcPeeringConnectionId",
        "NetworkInterfaceId",
        "InstanceId",
        "EgressOnlyInternetGatewayId",
        "LocalGatewayId",
        "CarrierGatewayId",
        "CoreNetworkArn",
        "VpcEndpointId",
    ];
    for k in KEYS {
        if let Some(v) = r.get(*k).and_then(|x| x.as_str()) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn parse_vpc_peerings(json: &Value, region: Option<&str>) -> Vec<NetworkServiceEntry> {
    let mut out = Vec::new();
    let Some(arr) = json
        .get("VpcPeeringConnections")
        .and_then(|v| v.as_array())
    else {
        return out;
    };
    for p in arr {
        let id = p
            .get("VpcPeeringConnectionId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let status = p
            .pointer("/Status/Code")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let requester = p
            .pointer("/RequesterVpcInfo/VpcId")
            .and_then(|x| x.as_str());
        let accepter = p
            .pointer("/AccepterVpcInfo/VpcId")
            .and_then(|x| x.as_str());
        let mut related = Vec::new();
        if let Some(a) = accepter {
            related.push(a.to_string());
        }
        let mut cidrs = Vec::new();
        for path in [
            "/RequesterVpcInfo/CidrBlock",
            "/AccepterVpcInfo/CidrBlock",
        ] {
            if let Some(c) = p.pointer(path).and_then(|x| x.as_str()) {
                cidrs.push(c.to_string());
            }
        }
        out.push(NetworkServiceEntry {
            id,
            name: tag_name(p.get("Tags")),
            service_type: "peering".into(),
            status,
            vpc_id: requester.map(|s| s.to_string()),
            related_ids: related,
            cidrs,
            region: region.map(|s| s.to_string()),
            description: Some("vpc_peering".into()),
        });
    }
    out
}

fn parse_transit_gateways(json: &Value, region: Option<&str>) -> Vec<NetworkServiceEntry> {
    let mut out = Vec::new();
    let Some(arr) = json.get("TransitGateways").and_then(|v| v.as_array()) else {
        return out;
    };
    for t in arr {
        let id = t
            .get("TransitGatewayId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        out.push(NetworkServiceEntry {
            id,
            name: tag_name(t.get("Tags")),
            service_type: "transit_gateway".into(),
            status: t
                .get("State")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            vpc_id: None,
            related_ids: t
                .get("OwnerId")
                .and_then(|x| x.as_str())
                .map(|s| vec![s.to_string()])
                .unwrap_or_default(),
            cidrs: vec![],
            region: region.map(|s| s.to_string()),
            description: t
                .get("Description")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
        });
    }
    out
}

fn parse_vpn_connections(json: &Value, region: Option<&str>) -> Vec<NetworkServiceEntry> {
    let mut out = Vec::new();
    let Some(arr) = json.get("VpnConnections").and_then(|v| v.as_array()) else {
        return out;
    };
    for v in arr {
        let id = v
            .get("VpnConnectionId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let mut related = Vec::new();
        for k in ["VpnGatewayId", "TransitGatewayId", "CustomerGatewayId"] {
            if let Some(x) = v.get(k).and_then(|x| x.as_str()) {
                related.push(x.to_string());
            }
        }
        out.push(NetworkServiceEntry {
            id,
            name: tag_name(v.get("Tags")),
            service_type: "vpn".into(),
            status: v
                .get("State")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            vpc_id: None,
            related_ids: related,
            cidrs: vec![],
            region: region.map(|s| s.to_string()),
            description: v
                .get("Type")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
        });
    }
    out
}

fn parse_vpc_endpoints(json: &Value, region: Option<&str>) -> Vec<NetworkServiceEntry> {
    let mut out = Vec::new();
    let Some(arr) = json.get("VpcEndpoints").and_then(|v| v.as_array()) else {
        return out;
    };
    for e in arr {
        let id = e
            .get("VpcEndpointId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let service = e
            .get("ServiceName")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let mut related = Vec::new();
        if let Some(ref s) = service {
            related.push(s.clone());
        }
        out.push(NetworkServiceEntry {
            id,
            name: tag_name(e.get("Tags")).or(service.clone()),
            service_type: "private_endpoint".into(),
            status: e
                .get("State")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            vpc_id: e
                .get("VpcId")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            related_ids: related,
            cidrs: vec![],
            region: region.map(|s| s.to_string()),
            description: e
                .get("VpcEndpointType")
                .and_then(|x| x.as_str())
                .map(|s| format!("vpc_endpoint:{s}")),
        });
    }
    out
}

fn parse_nat_gateways(json: &Value, region: Option<&str>) -> Vec<NetworkServiceEntry> {
    let mut out = Vec::new();
    let Some(arr) = json.get("NatGateways").and_then(|v| v.as_array()) else {
        return out;
    };
    for n in arr {
        let id = n
            .get("NatGatewayId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        out.push(NetworkServiceEntry {
            id,
            name: tag_name(n.get("Tags")),
            service_type: "nat_gateway".into(),
            status: n
                .get("State")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            vpc_id: n
                .get("VpcId")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            related_ids: n
                .get("SubnetId")
                .and_then(|x| x.as_str())
                .map(|s| vec![s.to_string()])
                .unwrap_or_default(),
            cidrs: vec![],
            region: region.map(|s| s.to_string()),
            description: n
                .get("ConnectivityType")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
        });
    }
    out
}

fn parse_internet_gateways(json: &Value, region: Option<&str>) -> Vec<NetworkServiceEntry> {
    let mut out = Vec::new();
    let Some(arr) = json.get("InternetGateways").and_then(|v| v.as_array()) else {
        return out;
    };
    for g in arr {
        let id = g
            .get("InternetGatewayId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let vpc = g
            .get("Attachments")
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .and_then(|a| a.get("VpcId"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        out.push(NetworkServiceEntry {
            id,
            name: tag_name(g.get("Tags")),
            service_type: "internet_gateway".into(),
            status: g
                .get("Attachments")
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|a| a.get("State"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            vpc_id: vpc,
            related_ids: vec![],
            cidrs: vec![],
            region: region.map(|s| s.to_string()),
            description: Some("igw".into()),
        });
    }
    out
}

fn parse_prefix_lists(json: &Value, region: Option<&str>) -> Vec<NetworkServiceEntry> {
    let mut out = Vec::new();
    let Some(arr) = json
        .get("PrefixLists")
        .or_else(|| json.get("ManagedPrefixLists"))
        .and_then(|v| v.as_array())
    else {
        return out;
    };
    for p in arr {
        let id = p
            .get("PrefixListId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let name = p
            .get("PrefixListName")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .or_else(|| tag_name(p.get("Tags")));
        out.push(NetworkServiceEntry {
            id,
            name,
            service_type: "prefix_list".into(),
            status: p
                .get("State")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            vpc_id: None,
            related_ids: vec![],
            cidrs: vec![],
            region: region.map(|s| s.to_string()),
            description: p
                .get("OwnerId")
                .and_then(|x| x.as_str())
                .map(|s| format!("owner={s}")),
        });
    }
    out
}

fn parse_dx_connections(json: &Value, region: Option<&str>) -> Vec<NetworkServiceEntry> {
    let mut out = Vec::new();
    // directconnect describe-connections → connections array
    let arr = json
        .get("connections")
        .or_else(|| json.get("Connections"))
        .and_then(|v| v.as_array());
    let Some(arr) = arr else {
        return out;
    };
    for c in arr {
        let id = c
            .get("connectionId")
            .or_else(|| c.get("ConnectionId"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let name = c
            .get("connectionName")
            .or_else(|| c.get("ConnectionName"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        out.push(NetworkServiceEntry {
            id,
            name,
            service_type: "hybrid".into(),
            status: c
                .get("connectionState")
                .or_else(|| c.get("ConnectionState"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            vpc_id: None,
            related_ids: c
                .get("region")
                .or_else(|| c.get("Region"))
                .and_then(|x| x.as_str())
                .map(|s| vec![s.to_string()])
                .unwrap_or_default(),
            cidrs: vec![],
            region: region.map(|s| s.to_string()),
            description: Some("direct_connect".into()),
        });
    }
    out
}

fn parse_lambda_functions(json: &Value, region: Option<&str>) -> Vec<FunctionEntry> {
    let mut out = Vec::new();
    let Some(arr) = json.get("Functions").and_then(|v| v.as_array()) else {
        return out;
    };
    for f in arr {
        let name = f
            .get("FunctionName")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let arn = f
            .get("FunctionArn")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let id = arn
            .clone()
            .or_else(|| name.clone())
            .unwrap_or_default();
        if id.is_empty() {
            continue;
        }
        let vpc_id = f
            .pointer("/VpcConfig/VpcId")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        out.push(FunctionEntry {
            id,
            name,
            runtime: f
                .get("Runtime")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            region: region.map(|s| s.to_string()),
            vpc_id,
            arn_or_url: arn,
        });
    }
    out
}

/// Minimal fixture inventory used by CLI seed + unit tests.
pub fn fixture_network_inventory(profile_id: &str) -> NetworkInventory {
    let vpcs = serde_json::json!({
        "Vpcs": [{
            "VpcId": "vpc-0abc",
            "CidrBlock": "10.0.0.0/16",
            "Tags": [{"Key": "Name", "Value": "main-prod"}],
            "CidrBlockAssociationSet": [
                {"CidrBlock": "10.0.0.0/16"},
                {"CidrBlock": "10.1.0.0/16"}
            ]
        }]
    });
    let subnets = serde_json::json!({
        "Subnets": [
            {
                "SubnetId": "subnet-app-a",
                "VpcId": "vpc-0abc",
                "CidrBlock": "10.0.4.0/24",
                "AvailabilityZone": "us-east-1a",
                "Tags": [{"Key": "Name", "Value": "app-a"}]
            },
            {
                "SubnetId": "subnet-db",
                "VpcId": "vpc-0abc",
                "CidrBlock": "10.0.8.0/24",
                "AvailabilityZone": "us-east-1b",
                "Tags": [{"Key": "Name", "Value": "db-tier"}]
            }
        ]
    });
    let enis = serde_json::json!({
        "NetworkInterfaces": [{
            "NetworkInterfaceId": "eni-1",
            "VpcId": "vpc-0abc",
            "SubnetId": "subnet-app-a",
            "PrivateIpAddress": "10.0.4.12",
            "PrivateIpAddresses": [
                {
                    "PrivateIpAddress": "10.0.4.12",
                    "Association": {"PublicIp": "54.1.2.3"}
                }
            ],
            "TagSet": [{"Key": "Name", "Value": "api-eni"}]
        }]
    });
    let sgs = serde_json::json!({
        "SecurityGroups": [{
            "GroupId": "sg-web",
            "GroupName": "web-sg",
            "Description": "web tier",
            "VpcId": "vpc-0abc",
            "Tags": [{"Key": "Name", "Value": "web-sg"}]
        }]
    });
    let nacls = serde_json::json!({
        "NetworkAcls": [{
            "NetworkAclId": "acl-private",
            "VpcId": "vpc-0abc",
            "IsDefault": false,
            "Tags": [{"Key": "Name", "Value": "private-nacl"}]
        }]
    });
    let rts = serde_json::json!({
        "RouteTables": [{
            "RouteTableId": "rtb-public",
            "VpcId": "vpc-0abc",
            "Tags": [{"Key": "Name", "Value": "public-rt"}],
            "Routes": [
                {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"},
                {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}
            ]
        }]
    });
    let lambdas = serde_json::json!({
        "Functions": [{
            "FunctionName": "api-handler",
            "FunctionArn": "arn:aws:lambda:us-east-1:123:function:api-handler",
            "Runtime": "python3.12",
            "VpcConfig": {"VpcId": "vpc-0abc"}
        }]
    });
    let peerings = serde_json::json!({
        "VpcPeeringConnections": [{
            "VpcPeeringConnectionId": "pcx-abc",
            "Status": {"Code": "active"},
            "RequesterVpcInfo": {"VpcId": "vpc-0abc", "CidrBlock": "10.0.0.0/16"},
            "AccepterVpcInfo": {"VpcId": "vpc-shared", "CidrBlock": "10.9.0.0/16"},
            "Tags": [{"Key": "Name", "Value": "to-shared"}]
        }]
    });
    let tgws = serde_json::json!({
        "TransitGateways": [{
            "TransitGatewayId": "tgw-hub",
            "State": "available",
            "Tags": [{"Key": "Name", "Value": "hub-tgw"}]
        }]
    });
    map_aws_network_full(
        profile_id,
        Some("us-east-1".into()),
        &vpcs,
        &subnets,
        Some(&enis),
        None,
        Some(&sgs),
        Some(&nacls),
        Some(&rts),
        Some(&lambdas),
        Some(&peerings),
        Some(&tgws),
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::{MatchMode, PatternQuery, ResourceKind};
    use oscar_tools::scan_network_inventory;

    #[test]
    fn maps_vpc_subnet_and_ips() {
        let inv = fixture_network_inventory("aws-prod");
        assert_eq!(inv.cloud, Cloud::Aws);
        assert_eq!(inv.vpcs.len(), 1);
        assert_eq!(inv.vpcs[0].name.as_deref(), Some("main-prod"));
        assert!(inv.vpcs[0].secondary_cidrs.contains(&"10.1.0.0/16".into()));
        assert_eq!(inv.subnets.len(), 2);
        assert!(inv.addresses.iter().any(|a| a.ip == "10.0.4.12"));
        assert!(inv.addresses.iter().any(|a| a.ip == "54.1.2.3"));
        assert!(inv.security_groups.iter().any(|s| s.id == "sg-web"));
        assert!(inv.nacls.iter().any(|n| n.id == "acl-private"));
        assert!(inv.route_tables.iter().any(|r| r.id == "rtb-public"));
        assert!(inv.routes.iter().any(|r| r.destination == "0.0.0.0/0"));
        assert!(inv.functions.iter().any(|f| f.name.as_deref() == Some("api-handler")));
        assert!(inv.services.iter().any(|s| s.service_type == "peering"));
        assert!(inv.services.iter().any(|s| s.service_type == "transit_gateway"));
    }

    #[test]
    fn pattern_partial_cidr_hits_subnet_from_mapped_inventory() {
        let inv = fixture_network_inventory("aws-prod");
        let q = PatternQuery {
            pattern: "10.0.4".into(),
            mode: MatchMode::Partial,
            profile_id: None,
            region: None,
            limit: 50,
        };
        let r = scan_network_inventory(&inv, &q);
        assert!(r.hit_count > 0, "expected hits for 10.0.4, got notes={:?}", r.notes);
        assert!(
            r.hits.iter().any(|h| h.kind == ResourceKind::Subnet),
            "expected subnet hit, hits={:?}",
            r.hits
        );
        assert!(r.hits.iter().all(|h| h.score > 0));
    }

    #[test]
    fn pattern_name_fragment_hits_vpc() {
        let inv = fixture_network_inventory("aws-prod");
        let q = PatternQuery {
            pattern: "main-prod".into(),
            mode: MatchMode::Partial,
            profile_id: None,
            region: None,
            limit: 20,
        };
        let r = scan_network_inventory(&inv, &q);
        assert!(r.hits.iter().any(|h| h.kind == ResourceKind::Vpc));
    }

    #[test]
    fn pattern_ip_locate_hits_address() {
        let inv = fixture_network_inventory("aws-prod");
        let q = PatternQuery {
            pattern: "10.0.4.12".into(),
            mode: MatchMode::IpOrCidr,
            profile_id: None,
            region: None,
            limit: 20,
        };
        let r = scan_network_inventory(&inv, &q);
        assert!(
            r.hits
                .iter()
                .any(|h| h.kind == ResourceKind::IpAddress || h.kind == ResourceKind::Subnet),
            "hits={:?}",
            r.hits
        );
    }

    #[test]
    fn pattern_hits_sg_nacl_rt_lambda() {
        let inv = fixture_network_inventory("aws-prod");
        for (pat, kind) in [
            ("web-sg", ResourceKind::SecurityGroup),
            ("private-nacl", ResourceKind::Nacl),
            ("public-rt", ResourceKind::RouteTable),
            ("0.0.0.0/0", ResourceKind::Route),
            ("api-handler", ResourceKind::Function),
            ("to-shared", ResourceKind::Peering),
            ("hub-tgw", ResourceKind::TransitGateway),
        ] {
            let q = PatternQuery {
                pattern: pat.into(),
                mode: MatchMode::Partial,
                profile_id: None,
                region: None,
                limit: 20,
            };
            let r = scan_network_inventory(&inv, &q);
            assert!(
                r.hits.iter().any(|h| h.kind == kind),
                "pattern {pat} should hit {kind:?}, hits={:?}",
                r.hits
            );
        }
    }
}
