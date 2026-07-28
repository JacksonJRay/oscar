//! AWS first-class tools: DNS, network path, IAM access, and pattern discovery.

mod aws_runtime;
mod dns;
mod iam;
pub mod map_network;
mod network;
mod network_write;
mod path_live;
mod resolver;
mod ssm;
pub mod sync_dns;
pub mod sync_network;
pub mod sync_resolver;

pub use map_network::{
    fixture_network_inventory, map_aws_ec2_to_network_inventory, map_aws_network_full,
    map_aws_to_network_inventory,
};
pub use sync_dns::AwsDnsSource;
pub use sync_network::AwsNetworkSource;
pub use sync_resolver::{AwsDnsResolverSource, DnsResolverInventorySource};

use oscar_tools::ToolRegistry;
use std::sync::Arc;

pub fn register(registry: &mut ToolRegistry) {
    // DNS
    registry.register(Arc::new(dns::AwsDnsZonesList));
    registry.register(Arc::new(dns::AwsDnsRecordLookup));
    registry.register(Arc::new(dns::AwsDnsPatternSearch));
    registry.register(Arc::new(dns::AwsDnsInventorySync));
    registry.register(Arc::new(dns::AwsDnsRecordCreate));
    registry.register(Arc::new(dns::AwsDnsRecordDelete));
    // Route 53 Resolver / DNS Firewall / query logs (Track C)
    registry.register(Arc::new(resolver::AwsDnsResolverInventorySync));
    registry.register(Arc::new(resolver::AwsDnsResolverPatternSearch));
    registry.register(Arc::new(resolver::AwsDnsFirewallPatternSearch));
    registry.register(Arc::new(resolver::AwsDnsQueryLogPatternSearch));
    registry.register(Arc::new(resolver::AwsDnsProfilePatternSearch));
    // Network (+ SG / NACL / routes / Lambda pattern search)
    registry.register(Arc::new(network::AwsNetworkPathAnalyze));
    registry.register(Arc::new(network::AwsNetworkAccessAnalyze));
    registry.register(Arc::new(network::AwsNetworkPatternSearch));
    registry.register(Arc::new(network::AwsNetworkSubnetPattern));
    registry.register(Arc::new(network::AwsNetworkVpcPattern));
    registry.register(Arc::new(network::AwsNetworkSgPattern));
    registry.register(Arc::new(network::AwsNetworkNaclPattern));
    registry.register(Arc::new(network::AwsNetworkRouteTablePattern));
    registry.register(Arc::new(network::AwsNetworkRoutePattern));
    registry.register(Arc::new(network::AwsComputeFunctionPattern));
    registry.register(Arc::new(network::AwsNetworkPeeringPattern));
    registry.register(Arc::new(network::AwsNetworkTgwPattern));
    registry.register(Arc::new(network::AwsNetworkVpnPattern));
    registry.register(Arc::new(network::AwsNetworkEndpointPattern));
    registry.register(Arc::new(network::AwsNetworkNatPattern));
    registry.register(Arc::new(network::AwsNetworkIgwPattern));
    registry.register(Arc::new(network::AwsNetworkHybridPattern));
    registry.register(Arc::new(network::AwsNetworkPrefixListPattern));
    registry.register(Arc::new(network::AwsNetworkServicePattern));
    registry.register(Arc::new(network::AwsNetworkIpLocate));
    registry.register(Arc::new(network::AwsNetworkInventorySync));
    // Network write (create/delete) — Capability::Write, mode-gated
    network_write::register_network_write(registry);
    // IAM / access (users, roles, groups, policies, simulate/test)
    iam::register_iam(registry);
    // SSM Run Command — agent passes plain command; oscar encodes for SSM
    ssm::register_ssm(registry);
}
