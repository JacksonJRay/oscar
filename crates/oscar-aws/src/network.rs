use crate::sync_network::AwsNetworkSource;
use async_trait::async_trait;
use oscar_core::{Capability, Cloud, PatternQuery, ToolDomain};
use oscar_tools::sync::NetworkInventorySource;
use oscar_tools::{
    auth_for, discovery_blurb, discovery_tool_result, ensure_network_inventory, load_network_cache,
    pattern_properties, scan_network_inventory, to_tool_result, write_network_cache, Tool,
    ToolContext, ToolMeta, ToolResult,
};
use serde_json::json;

pub use crate::path_live::{AwsNetworkAccessAnalyze, AwsNetworkPathAnalyze};
pub struct AwsNetworkPatternSearch;
pub struct AwsNetworkSubnetPattern;
pub struct AwsNetworkVpcPattern;
pub struct AwsNetworkIpLocate;
pub struct AwsNetworkSgPattern;
pub struct AwsNetworkNaclPattern;
pub struct AwsNetworkRouteTablePattern;
pub struct AwsNetworkRoutePattern;
pub struct AwsComputeFunctionPattern;
pub struct AwsNetworkPeeringPattern;
pub struct AwsNetworkTgwPattern;
pub struct AwsNetworkVpnPattern;
pub struct AwsNetworkEndpointPattern;
pub struct AwsNetworkNatPattern;
pub struct AwsNetworkIgwPattern;
pub struct AwsNetworkHybridPattern;
pub struct AwsNetworkPrefixListPattern;
pub struct AwsNetworkServicePattern;
pub struct AwsNetworkInventorySync;

async fn run_network_pattern(
    args: serde_json::Value,
    ctx: &ToolContext,
    kinds_filter: Option<&[&str]>,
    scope_label: &str,
) -> ToolResult {
    let q = match PatternQuery::from_args(&args) {
        Ok(q) => q,
        Err(e) => return ToolResult::error(e),
    };
    let profiles = ctx.profiles_for(Cloud::Aws, q.profile_id.as_deref());
    if profiles.is_empty() {
        return ToolResult::needs_auth(auth_for(
            Cloud::Aws,
            format!("AWS profile required for network pattern search `{}`", q.pattern),
        ));
    }

    let force = args
        .get("refresh")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut merged = oscar_core::DiscoveryResult::empty(
        &q.pattern,
        q.mode,
        format!("aws.{scope_label}:{} profiles", profiles.len()),
    );
    let source = AwsNetworkSource;
    let mut any = false;
    for p in profiles {
        let inv = match ensure_network_inventory(
            &ctx.config_dir,
            p,
            &source,
            q.region.as_deref(),
            force,
        )
        .await
        {
            Ok(inv) => {
                any = true;
                inv
            }
            Err(e) => {
                merged.partial = true;
                merged.notes.push(format!("profile `{}`: {e}", p.id));
                if let Some(cached) = load_network_cache(&ctx.config_dir, &p.id, q.region.as_deref())
                {
                    any = true;
                    cached
                } else {
                    continue;
                }
            }
        };
        let mut part = scan_network_inventory(&inv, &q);
        if let Some(filters) = kinds_filter {
            part.hits.retain(|h| {
                let k = h.kind.to_string();
                filters.iter().any(|f| k == *f)
            });
        }
        merged.hits.append(&mut part.hits);
    }
    if !any {
        merged.partial = true;
        merged.notes.push(
            "No AWS network inventory. Run aws.network.inventory.sync or: oscar inventory sync --cloud aws --kind network (or seed-fixture).".into(),
        );
    }
    merged.hits.truncate(q.limit);
    to_tool_result(discovery_tool_result(merged.finalize()))
}

fn pattern_meta(id: &str, name: &str, desc: &str, tags: &[&str]) -> ToolMeta {
    ToolMeta {
        id: id.into(),
        name: name.into(),
        description: discovery_blurb(desc),
        domain: ToolDomain::Network,
        clouds: vec![Cloud::Aws],
        capability: Capability::Read,
        tags: tags.iter().map(|s| (*s).to_string()).collect(),
        input_schema: json!({
            "type": "object",
            "properties": pattern_properties(),
            "required": ["pattern"]
        }),
        output_schema: None,
    }
}

#[async_trait]
impl Tool for AwsNetworkInventorySync {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.network.inventory.sync".into(),
            name: "Sync VPC fabric into NetworkInventory".into(),
            description: "Live-fetch AWS VPCs, subnets, ENI/EIP, SG, NACL, routes, Lambda, VPC peering, TGW, VPN, VPC endpoints/PrivateLink, NAT, IGW, prefix lists, Direct Connect via aws CLI → NetworkInventory for pattern search.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "sync".into(),
                "inventory".into(),
                "vpc".into(),
                "subnet".into(),
                "security-group".into(),
                "nacl".into(),
                "route-table".into(),
                "lambda".into(),
                "peering".into(),
                "tgw".into(),
                "vpn".into(),
                "endpoint".into(),
                "nat".into(),
                "direct-connect".into(),
                "cache".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" },
                    "region": { "type": "string" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profiles = ctx.profiles_for(Cloud::Aws, args.get("profile_id").and_then(|v| v.as_str()),
        );
        if profiles.is_empty() {
            return ToolResult::needs_auth(auth_for(
                Cloud::Aws,
                "AWS profile required to sync network inventory",
            ));
        }
        let region = args.get("region").and_then(|v| v.as_str());
        let source = AwsNetworkSource;
        let mut details = Vec::new();
        let mut vpcs = 0usize;
        let mut subnets = 0usize;
        let mut addrs = 0usize;
        let mut sgs = 0usize;
        let mut nacls = 0usize;
        let mut rts = 0usize;
        let mut routes = 0usize;
        let mut funcs = 0usize;
        let mut services = 0usize;
        for p in profiles {
            let r = region.or(p.default_region.as_deref());
            match source.sync_network(p, r).await {
                Ok(inv) => {
                    vpcs += inv.vpcs.len();
                    subnets += inv.subnets.len();
                    addrs += inv.addresses.len();
                    sgs += inv.security_groups.len();
                    nacls += inv.nacls.len();
                    rts += inv.route_tables.len();
                    routes += inv.routes.len();
                    funcs += inv.functions.len();
                    services += inv.services.len();
                    let _ = write_network_cache(&ctx.config_dir, &inv);
                    details.push(format!(
                        "{}: vpcs={} subnets={} sgs={} services={} (peering/tgw/vpn/endpoint/nat/…)",
                        p.id,
                        inv.vpcs.len(),
                        inv.subnets.len(),
                        inv.security_groups.len(),
                        inv.services.len()
                    ));
                }
                Err(e) => details.push(format!("{}: ERROR {e}", p.id)),
            }
        }
        ToolResult::success(
            format!(
                "AWS network sync: {vpcs} vpcs, {subnets} subnets, {addrs} addresses, {sgs} sgs, {nacls} nacls, {rts} route tables, {routes} routes, {funcs} functions, {services} services"
            ),
            json!({
                "cloud": "aws",
                "format": "NetworkInventory",
                "vpcs": vpcs,
                "subnets": subnets,
                "addresses": addrs,
                "security_groups": sgs,
                "nacls": nacls,
                "route_tables": rts,
                "routes": routes,
                "functions": funcs,
                "services": services,
                "details": details
            }),
        )
    }
}

#[async_trait]
impl Tool for AwsNetworkPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.pattern.search",
                "Pattern search VPCs, subnets, IPs, SGs, NACLs, routes, Lambdas",
                "AWS VPCs, subnets, addresses, security groups, NACLs, route tables/routes, and Lambda functions — partial name, IP fragment, or CIDR",
                &[
                    "network", "pattern", "search", "discover", "partial", "subnet", "vpc", "ip",
                    "cidr", "security-group", "nacl", "route-table", "route", "lambda", "function",
                    "peering", "tgw", "vpn", "endpoint", "nat", "igw", "direct-connect", "prefix-list",
                ],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, None, "network.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkSubnetPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.subnet.pattern",
                "Pattern search subnets only",
                "AWS subnets only — partial CIDR/name match (e.g. 10.0.4, app-*, subnet-abc)",
                &["subnet", "pattern", "search", "cidr", "partial", "network"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["subnet"]), "subnet.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkVpcPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.vpc.pattern",
                "Pattern search VPCs only",
                "AWS VPCs by id, name, or CIDR fragment",
                &["vpc", "pattern", "search", "cidr", "network"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["vpc"]), "vpc.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkSgPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.sg.pattern",
                "Pattern search security groups",
                "AWS EC2 security groups by id, name, description, or VPC",
                &["security-group", "sg", "pattern", "search", "firewall", "network", "partial"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["security_group"]), "sg.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkNaclPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.nacl.pattern",
                "Pattern search network ACLs",
                "AWS network ACLs (NACLs) by id, Name tag, or VPC",
                &["nacl", "network-acl", "pattern", "search", "network", "partial"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["nacl"]), "nacl.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkRouteTablePattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.route_table.pattern",
                "Pattern search route tables",
                "AWS route tables by id, name, VPC, destination CIDR, or gateway/NAT target",
                &["route-table", "rtb", "pattern", "search", "network", "partial"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["route_table"]), "route_table.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkRoutePattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.route.pattern",
                "Pattern search individual routes",
                "AWS routes by destination CIDR/prefix list or next-hop target (igw, nat, tgw, pcx)",
                &["route", "pattern", "search", "cidr", "network", "partial"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["route"]), "route.pattern").await
    }
}

#[async_trait]
impl Tool for AwsComputeFunctionPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.compute.function.pattern",
                "Pattern search Lambda functions",
                "AWS Lambda functions by name, ARN, runtime, or VPC",
                &["lambda", "function", "compute", "pattern", "search", "serverless", "partial"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["function"]), "function.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkServicePattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.service.pattern",
                "Pattern search all AWS network fabric services",
                "AWS peering, TGW, VPN, VPC endpoints, NAT, IGW, prefix lists, Direct Connect — one broad service search",
                &[
                    "network", "service", "pattern", "search", "peering", "tgw", "vpn",
                    "endpoint", "nat", "igw", "direct-connect", "prefix-list", "partial",
                ],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(
            args,
            ctx,
            Some(&[
                "peering",
                "transit_gateway",
                "vpn",
                "hybrid_connection",
                "private_endpoint",
                "nat_gateway",
                "internet_gateway",
                "network_share",
                "prefix_list",
                "load_balancer",
            ]),
            "service.pattern",
        )
        .await
    }
}

#[async_trait]
impl Tool for AwsNetworkPeeringPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.peering.pattern",
                "Pattern search VPC peerings",
                "AWS VPC peering connections by id, Name tag, requester/accepter VPC, or CIDR",
                &["peering", "vpc-peering", "pcx", "pattern", "search", "network", "partial"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["peering"]), "peering.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkTgwPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.tgw.pattern",
                "Pattern search Transit Gateways",
                "AWS Transit Gateways by id, Name, state, or owner",
                &["tgw", "transit-gateway", "pattern", "search", "network", "partial", "sharing"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["transit_gateway"]), "tgw.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkVpnPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.vpn.pattern",
                "Pattern search VPN connections",
                "AWS Site-to-Site VPN connections by id, Name, VGW/TGW/CGW, or state",
                &["vpn", "site-to-site", "pattern", "search", "network", "hybrid", "partial"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["vpn"]), "vpn.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkEndpointPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.endpoint.pattern",
                "Pattern search VPC endpoints / PrivateLink",
                "AWS VPC endpoints (Interface/Gateway PrivateLink) by id, service name, VPC, or state",
                &[
                    "endpoint", "privatelink", "vpc-endpoint", "pattern", "search", "network",
                    "private", "partial",
                ],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["private_endpoint"]), "endpoint.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkNatPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.nat.pattern",
                "Pattern search NAT gateways",
                "AWS NAT gateways by id, Name, VPC, subnet, or state",
                &["nat", "nat-gateway", "pattern", "search", "network", "egress", "partial"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["nat_gateway"]), "nat.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkIgwPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.igw.pattern",
                "Pattern search Internet Gateways",
                "AWS Internet Gateways by id, Name, or attached VPC",
                &["igw", "internet-gateway", "pattern", "search", "network", "partial"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["internet_gateway"]), "igw.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkHybridPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.hybrid.pattern",
                "Pattern search Direct Connect / hybrid links",
                "AWS Direct Connect connections by id, name, or state (hybrid on-prem connectivity)",
                &[
                    "direct-connect", "dx", "hybrid", "interconnect", "pattern", "search",
                    "network", "partial",
                ],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["hybrid_connection"]), "hybrid.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkPrefixListPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            pattern_meta(
                "aws.network.prefix_list.pattern",
                "Pattern search managed prefix lists",
                "AWS managed prefix lists by id or name (used in routes/SGs)",
                &["prefix-list", "pl", "pattern", "search", "network", "cidr", "partial"],
            )
        })
    }
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        run_network_pattern(args, ctx, Some(&["prefix_list"]), "prefix_list.pattern").await
    }
}

#[async_trait]
impl Tool for AwsNetworkIpLocate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "aws.network.ip.locate".into(),
            name: "Locate IP / IP fragment in AWS".into(),
            description: "Find which VPC/subnet/ENI-like address inventory contains an IP or partial IP (e.g. 10.0.4.12 or 10.0.4). Faster than Reachability Analyzer for ownership discovery.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Aws],
            capability: Capability::Read,
            tags: vec![
                "ip".into(),
                "locate".into(),
                "pattern".into(),
                "subnet".into(),
                "vpc".into(),
                "discover".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "IP, fragment, or CIDR" },
                    "ip": { "type": "string", "description": "Alias for pattern" },
                    "profile_id": { "type": "string" },
                    "region": { "type": "string" },
                    "limit": { "type": "integer", "default": 50 }
                },
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, mut args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Some(obj) = args.as_object_mut() {
            if !obj.contains_key("pattern") {
                if let Some(ip) = obj.get("ip").cloned() {
                    obj.insert("pattern".into(), ip);
                }
            }
            obj.insert("mode".into(), json!("ip_or_cidr"));
        }
        run_network_pattern(args, ctx, None, "ip.locate").await
    }
}
