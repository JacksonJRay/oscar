//! Cached resource inventories used by pattern-search tools.
//!
//! Live CSP sync fills these shapes; pattern tools always run the same matcher
//! over inventory so discovery stays consistent and token-efficient.

use oscar_core::{Cloud, ClusterRef};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInventory {
    pub profile_id: String,
    pub cloud: Cloud,
    #[serde(default)]
    pub zones: Vec<DnsZoneEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZoneEntry {
    pub id: String,
    pub name: String,
    pub private: bool,
    #[serde(default)]
    pub vpc_or_network_ids: Vec<String>,
    #[serde(default)]
    pub records: Vec<DnsRecordEntry>,
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecordEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default)]
    pub ttl: Option<u32>,
}

/// Private DNS forwarding / resolver inventory — unified across CSPs (Track C).
///
/// Covers Route 53 Resolver, DNS Firewall, query logs, R53 Profiles, GCP DNS
/// policies / response policies, Azure Private DNS links, and Private Resolvers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolverInventory {
    pub profile_id: String,
    pub cloud: Cloud,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub endpoints: Vec<ResolverEndpointEntry>,
    #[serde(default)]
    pub rules: Vec<ResolverRuleEntry>,
    #[serde(default)]
    pub firewall_rule_groups: Vec<FirewallRuleGroupEntry>,
    #[serde(default)]
    pub query_log_configs: Vec<QueryLogConfigEntry>,
    /// AWS Route 53 Profiles (C2) or shared DNS profile objects.
    #[serde(default)]
    pub profiles: Vec<DnsProfileEntry>,
    /// GCP Cloud DNS policies, response policies, forwarding narrative rows (C5/C6).
    #[serde(default)]
    pub policies: Vec<DnsPolicyEntry>,
    /// Azure Private DNS virtual network links (C7).
    #[serde(default)]
    pub vnet_links: Vec<DnsVnetLinkEntry>,
    /// Azure DNS Private Resolver (or CSP equivalent) (C8).
    #[serde(default)]
    pub private_resolvers: Vec<DnsPrivateResolverEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProfileEntry {
    pub id: String,
    pub name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub share_status: Option<String>,
    #[serde(default)]
    pub associations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsPolicyEntry {
    pub id: String,
    pub name: Option<String>,
    /// policy | response_policy | forwarding_zone | peering_zone
    #[serde(default)]
    pub policy_type: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub alternative_name_servers: Vec<String>,
    #[serde(default)]
    pub enable_inbound_forwarding: Option<bool>,
    #[serde(default)]
    pub enable_logging: Option<bool>,
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsVnetLinkEntry {
    pub id: String,
    pub name: Option<String>,
    pub zone_name: String,
    #[serde(default)]
    pub vnet_id: Option<String>,
    #[serde(default)]
    pub registration_enabled: Option<bool>,
    #[serde(default)]
    pub provisioning_state: Option<String>,
    #[serde(default)]
    pub resolution_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsPrivateResolverEntry {
    pub id: String,
    pub name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub vnet_id: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    /// inbound | outbound | ruleset summary lines
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub rulesets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverEndpointEntry {
    pub id: String,
    pub name: Option<String>,
    /// INBOUND | OUTBOUND
    pub direction: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub vpc_id: Option<String>,
    #[serde(default)]
    pub subnet_ids: Vec<String>,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    #[serde(default)]
    pub security_group_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverRuleEntry {
    pub id: String,
    pub name: Option<String>,
    /// FORWARD | SYSTEM | RECURSIVE
    #[serde(default)]
    pub rule_type: Option<String>,
    pub domain_name: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub resolver_endpoint_id: Option<String>,
    #[serde(default)]
    pub target_ips: Vec<String>,
    #[serde(default)]
    pub vpc_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleGroupEntry {
    pub id: String,
    pub name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub rule_count: Option<u32>,
    #[serde(default)]
    pub share_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogConfigEntry {
    pub id: String,
    pub name: Option<String>,
    #[serde(default)]
    pub destination_arn: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub association_count: Option<u32>,
    #[serde(default)]
    pub owner_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInventory {
    pub profile_id: String,
    pub cloud: Cloud,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub vpcs: Vec<VpcEntry>,
    #[serde(default)]
    pub subnets: Vec<SubnetEntry>,
    #[serde(default)]
    pub addresses: Vec<AddressEntry>,
    /// AWS security groups / GCP firewall rules / Azure NSGs.
    #[serde(default)]
    pub security_groups: Vec<SecurityGroupEntry>,
    /// AWS network ACLs (empty on GCP/Azure where firewall/NSG covers the role).
    #[serde(default)]
    pub nacls: Vec<NaclEntry>,
    /// Route tables (AWS RT, Azure route table; GCP may use a synthetic global table).
    #[serde(default)]
    pub route_tables: Vec<RouteTableEntry>,
    /// Individual routes for dest-CIDR / next-hop pattern search.
    #[serde(default)]
    pub routes: Vec<RouteEntry>,
    /// Serverless functions (Lambda / Cloud Functions / Azure Functions).
    #[serde(default)]
    pub functions: Vec<FunctionEntry>,
    /// Cross-cloud network services: peering, TGW, VPN, hybrid (DX/ER), private endpoints,
    /// NAT/IGW, network shares, prefix lists, load balancers (when inventoried).
    #[serde(default)]
    pub services: Vec<NetworkServiceEntry>,
}

/// Unified network service row for pattern discovery (peering, TGW, VPN, hybrid, endpoints, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkServiceEntry {
    pub id: String,
    pub name: Option<String>,
    /// Canonical type: peering | transit_gateway | vpn | hybrid | private_endpoint |
    /// nat_gateway | internet_gateway | network_share | prefix_list | load_balancer | other
    pub service_type: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub vpc_id: Option<String>,
    /// Related resource ids (peer VPC, TGW, attachment, remote VNet, service name, …).
    #[serde(default)]
    pub related_ids: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

impl NetworkServiceEntry {
    pub fn new(
        id: impl Into<String>,
        service_type: impl Into<String>,
        name: Option<String>,
        region: Option<&str>,
    ) -> Self {
        Self {
            id: id.into(),
            name,
            service_type: service_type.into(),
            status: None,
            vpc_id: None,
            related_ids: vec![],
            cidrs: vec![],
            region: region.map(|s| s.to_string()),
            description: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGroupEntry {
    pub id: String,
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub vpc_id: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NaclEntry {
    pub id: String,
    pub name: Option<String>,
    #[serde(default)]
    pub vpc_id: Option<String>,
    #[serde(default)]
    pub is_default: Option<bool>,
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTableEntry {
    pub id: String,
    pub name: Option<String>,
    #[serde(default)]
    pub vpc_id: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    /// Destination CIDRs / prefix lists summarized for search.
    #[serde(default)]
    pub destinations: Vec<String>,
    /// Gateway / NAT / peering / instance targets summarized for search.
    #[serde(default)]
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    /// Composite id (route-table + destination) when no native id.
    pub id: String,
    pub name: Option<String>,
    pub route_table_id: String,
    /// Destination CIDR, prefix list, or service endpoint.
    pub destination: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub vpc_id: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntry {
    pub id: String,
    pub name: Option<String>,
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub vpc_id: Option<String>,
    #[serde(default)]
    pub arn_or_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpcEntry {
    pub id: String,
    pub name: Option<String>,
    pub cidr: String,
    #[serde(default)]
    pub secondary_cidrs: Vec<String>,
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetEntry {
    pub id: String,
    pub name: Option<String>,
    pub cidr: String,
    pub vpc_id: String,
    #[serde(default)]
    pub az: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressEntry {
    pub id: Option<String>,
    pub name: Option<String>,
    pub ip: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub vpc_id: Option<String>,
    #[serde(default)]
    pub subnet_id: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sInventory {
    pub context: Option<String>,
    pub profile_id: Option<String>,
    pub resources: Vec<K8sResourceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sResourceEntry {
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub extra: Vec<String>,
}

pub fn cache_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("cache")
}

pub fn dns_cache_path(config_dir: &Path, profile_id: &str) -> PathBuf {
    cache_dir(config_dir).join(profile_id).join("dns.json")
}

pub fn network_cache_path(config_dir: &Path, profile_id: &str, region: Option<&str>) -> PathBuf {
    let name = match region {
        Some(r) => format!("network-{r}.json"),
        None => "network.json".into(),
    };
    cache_dir(config_dir).join(profile_id).join(name)
}

pub fn k8s_cache_path(config_dir: &Path, key: &str) -> PathBuf {
    cache_dir(config_dir).join("k8s").join(format!("{key}.json"))
}

pub fn dns_resolver_cache_path(
    config_dir: &Path,
    profile_id: &str,
    region: Option<&str>,
) -> PathBuf {
    let name = match region {
        Some(r) => format!("dns-resolver-{r}.json"),
        None => "dns-resolver.json".into(),
    };
    cache_dir(config_dir).join(profile_id).join(name)
}

pub fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn save_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    fs::write(path, raw)
}

/// List cluster refs from profiles for k8s discovery scoping.
pub fn clusters_from_profiles(
    profiles: &[oscar_identity::Profile],
) -> Vec<(String, Cloud, ClusterRef)> {
    let mut out = Vec::new();
    for p in profiles {
        for c in &p.clusters {
            out.push((p.id.clone(), p.cloud, c.clone()));
        }
    }
    out
}
