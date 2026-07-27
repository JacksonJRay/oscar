//! Pure AWS EC2 JSON → unified [`NetworkInventory`] (no CLI / network I/O).
//!
//! Tests and live sync both call this so the agent-facing shape stays stable.

use oscar_core::Cloud;
use oscar_tools::inventory::{AddressEntry, NetworkInventory, SubnetEntry, VpcEntry};
use serde_json::Value;

/// Build unified network inventory from AWS CLI JSON blobs.
///
/// Expected shapes match `aws ec2 describe-vpcs|describe-subnets|describe-network-interfaces
/// |describe-addresses --output json`.
pub fn map_aws_ec2_to_network_inventory(
    profile_id: impl Into<String>,
    region: Option<String>,
    vpcs_json: &Value,
    subnets_json: &Value,
    enis_json: Option<&Value>,
    eips_json: Option<&Value>,
) -> NetworkInventory {
    let profile_id = profile_id.into();
    let region_ref = region.clone();

    let vpcs = parse_vpcs(vpcs_json, region_ref.as_deref());
    let subnets = parse_subnets(subnets_json, region_ref.as_deref());
    let mut addresses = Vec::new();
    if let Some(enis) = enis_json {
        addresses.extend(parse_eni_addresses(enis, region_ref.as_deref()));
    }
    if let Some(eips) = eips_json {
        addresses.extend(parse_elastic_ips(eips, region_ref.as_deref()));
    }

    NetworkInventory {
        profile_id,
        cloud: Cloud::Aws,
        region,
        vpcs,
        subnets,
        addresses,
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
    map_aws_ec2_to_network_inventory(
        profile_id,
        Some("us-east-1".into()),
        &vpcs,
        &subnets,
        Some(&enis),
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
}
