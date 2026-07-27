//! AWS first-class tools: DNS, network path, IAM access, and pattern discovery.

mod aws_runtime;
mod dns;
mod iam;
pub mod map_network;
mod network;
mod path_live;
mod resolver;
pub mod sync_dns;
pub mod sync_network;
pub mod sync_resolver;

pub use map_network::{fixture_network_inventory, map_aws_ec2_to_network_inventory};
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
    // Network
    registry.register(Arc::new(network::AwsNetworkPathAnalyze));
    registry.register(Arc::new(network::AwsNetworkAccessAnalyze));
    registry.register(Arc::new(network::AwsNetworkPatternSearch));
    registry.register(Arc::new(network::AwsNetworkSubnetPattern));
    registry.register(Arc::new(network::AwsNetworkVpcPattern));
    registry.register(Arc::new(network::AwsNetworkIpLocate));
    registry.register(Arc::new(network::AwsNetworkInventorySync));
    // IAM / access (users, roles, groups, policies, simulate/test)
    iam::register_iam(registry);
}
