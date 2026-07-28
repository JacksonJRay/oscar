//! Run pattern matchers over DNS / network / k8s inventories.

use crate::inventory::{
    AddressEntry, DnsInventory, DnsRecordEntry, DnsResolverInventory, DnsZoneEntry, FunctionEntry,
    K8sInventory, K8sResourceEntry, NaclEntry, NetworkInventory, NetworkServiceEntry,
    ResolverEndpointEntry, ResolverRuleEntry, RouteEntry, RouteTableEntry, SecurityGroupEntry,
    SubnetEntry, VpcEntry,
};
use oscar_core::{
    best_field_match, match_text, Cloud, DiscoveryHit, DiscoveryResult, MatchMode, PatternQuery,
    ResourceKind,
};
use serde_json::json;

pub fn scan_dns_inventory(inv: &DnsInventory, q: &PatternQuery) -> DiscoveryResult {
    let mut result = DiscoveryResult::empty(
        &q.pattern,
        q.mode,
        format!("dns:{}:{}", inv.cloud, inv.profile_id),
    );
    // Partial name search also tries ip_or_cidr on record values (and vice versa).
    let modes = dual_modes(q.mode);

    for zone in &inv.zones {
        for mode in &modes {
            if let Some((field, value, score)) = best_field_match(
                &q.pattern,
                *mode,
                &[
                    ("zone_name", zone.name.as_str()),
                    ("zone_id", zone.id.as_str()),
                ],
            ) {
                result
                    .hits
                    .push(hit_dns_zone(inv, zone, field, value, score));
                break;
            }
        }

        for rec in &zone.records {
            push_dns_record_hits(&mut result, inv, zone, rec, q, &modes);
        }

        if result.hits.len() >= q.limit * 2 {
            break;
        }
    }

    result.hits.truncate(q.limit);
    result.finalize()
}

fn hit_dns_zone(
    inv: &DnsInventory,
    zone: &DnsZoneEntry,
    field: String,
    value: String,
    score: u32,
) -> DiscoveryHit {
    let mut attrs = serde_json::Map::new();
    attrs.insert("private".into(), json!(zone.private));
    if !zone.vpc_or_network_ids.is_empty() {
        attrs.insert("networks".into(), json!(zone.vpc_or_network_ids));
    }
    DiscoveryHit {
        kind: ResourceKind::DnsZone,
        cloud: inv.cloud,
        profile_id: Some(inv.profile_id.clone()),
        region: zone.region.clone(),
        name: zone.name.clone(),
        id: Some(zone.id.clone()),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    }
}

fn push_dns_record_hits(
    result: &mut DiscoveryResult,
    inv: &DnsInventory,
    zone: &DnsZoneEntry,
    rec: &DnsRecordEntry,
    q: &PatternQuery,
    modes: &[MatchMode],
) {
    let mut fields: Vec<(&str, String)> = vec![
        ("record_name", rec.name.clone()),
        ("record_type", rec.record_type.clone()),
        ("zone_name", zone.name.clone()),
    ];
    for v in &rec.values {
        fields.push(("record_value", v.clone()));
    }
    let field_refs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (*k, v.as_str()))
        .collect();

    // Try partial first, then ip_or_cidr (or reverse) so name fragments and IP targets both hit.
    let mut matched: Option<(String, String, u32)> = None;
    for mode in modes {
        if let Some(hit) = best_field_match(&q.pattern, *mode, &field_refs) {
            matched = Some(hit);
            break;
        }
    }
    if let Some((field, value, mut score)) = matched {
        // Boost when both name and zone align with a FQDN-ish query.
        if rec
            .name
            .to_ascii_lowercase()
            .contains(&q.pattern.to_ascii_lowercase())
        {
            score = score.saturating_add(5).min(100);
        }
        let mut attrs = serde_json::Map::new();
        attrs.insert("zone".into(), json!(zone.name));
        attrs.insert("zone_id".into(), json!(zone.id));
        attrs.insert("private_zone".into(), json!(zone.private));
        attrs.insert("type".into(), json!(rec.record_type));
        attrs.insert("values".into(), json!(rec.values));
        result.hits.push(DiscoveryHit {
            kind: ResourceKind::DnsRecord,
            cloud: inv.cloud,
            profile_id: Some(inv.profile_id.clone()),
            region: zone.region.clone(),
            name: rec.name.clone(),
            id: Some(format!("{}/{}", zone.id, rec.name)),
            matched_field: field,
            matched_value: value,
            score,
            attrs,
        });
    }
}

/// Pattern-scan Route 53 Resolver / DNS Firewall / query-log inventory.
pub fn scan_dns_resolver_inventory(inv: &DnsResolverInventory, q: &PatternQuery) -> DiscoveryResult {
    let mut result = DiscoveryResult::empty(
        &q.pattern,
        q.mode,
        format!(
            "dns-resolver:{}:{}:{}",
            inv.cloud,
            inv.profile_id,
            inv.region.as_deref().unwrap_or("all")
        ),
    );
    let modes = dual_modes(q.mode);

    for ep in &inv.endpoints {
        for mode in &modes {
            if let Some(hit) = match_resolver_endpoint(inv, ep, q, *mode) {
                result.hits.push(hit);
                break;
            }
        }
    }
    for rule in &inv.rules {
        for mode in &modes {
            if let Some(hit) = match_resolver_rule(inv, rule, q, *mode) {
                result.hits.push(hit);
                break;
            }
        }
    }
    for fg in &inv.firewall_rule_groups {
        if let Some((field, value, score)) = best_field_match(
            &q.pattern,
            q.mode,
            &[
                ("name", fg.name.as_deref().unwrap_or("")),
                ("id", fg.id.as_str()),
                ("status", fg.status.as_deref().unwrap_or("")),
                ("owner_id", fg.owner_id.as_deref().unwrap_or("")),
            ],
        ) {
            let mut attrs = serde_json::Map::new();
            if let Some(n) = &fg.name {
                attrs.insert("name".into(), json!(n));
            }
            if let Some(c) = fg.rule_count {
                attrs.insert("rule_count".into(), json!(c));
            }
            if let Some(s) = &fg.share_status {
                attrs.insert("share_status".into(), json!(s));
            }
            result.hits.push(DiscoveryHit {
                kind: ResourceKind::DnsFirewallRuleGroup,
                cloud: inv.cloud,
                profile_id: Some(inv.profile_id.clone()),
                region: inv.region.clone(),
                name: fg.name.clone().unwrap_or_else(|| fg.id.clone()),
                id: Some(fg.id.clone()),
                matched_field: field,
                matched_value: value,
                score,
                attrs,
            });
        }
    }
    for ql in &inv.query_log_configs {
        if let Some((field, value, score)) = best_field_match(
            &q.pattern,
            q.mode,
            &[
                ("name", ql.name.as_deref().unwrap_or("")),
                ("id", ql.id.as_str()),
                (
                    "destination_arn",
                    ql.destination_arn.as_deref().unwrap_or(""),
                ),
                ("status", ql.status.as_deref().unwrap_or("")),
            ],
        ) {
            let mut attrs = serde_json::Map::new();
            if let Some(d) = &ql.destination_arn {
                attrs.insert("destination_arn".into(), json!(d));
            }
            if let Some(c) = ql.association_count {
                attrs.insert("association_count".into(), json!(c));
            }
            result.hits.push(DiscoveryHit {
                kind: ResourceKind::DnsQueryLogConfig,
                cloud: inv.cloud,
                profile_id: Some(inv.profile_id.clone()),
                region: inv.region.clone(),
                name: ql.name.clone().unwrap_or_else(|| ql.id.clone()),
                id: Some(ql.id.clone()),
                matched_field: field,
                matched_value: value,
                score,
                attrs,
            });
        }
    }

    for pr in &inv.profiles {
        if let Some((field, value, score)) = best_field_match(
            &q.pattern,
            q.mode,
            &[
                ("name", pr.name.as_deref().unwrap_or("")),
                ("id", pr.id.as_str()),
                ("status", pr.status.as_deref().unwrap_or("")),
                ("owner_id", pr.owner_id.as_deref().unwrap_or("")),
            ],
        ) {
            let mut attrs = serde_json::Map::new();
            if let Some(s) = &pr.share_status {
                attrs.insert("share_status".into(), json!(s));
            }
            if !pr.associations.is_empty() {
                attrs.insert("associations".into(), json!(pr.associations));
            }
            result.hits.push(DiscoveryHit {
                kind: ResourceKind::DnsProfile,
                cloud: inv.cloud,
                profile_id: Some(inv.profile_id.clone()),
                region: inv.region.clone(),
                name: pr.name.clone().unwrap_or_else(|| pr.id.clone()),
                id: Some(pr.id.clone()),
                matched_field: field,
                matched_value: value,
                score,
                attrs,
            });
        }
    }

    for pol in &inv.policies {
        let mut fields = vec![
            ("name", pol.name.as_deref().unwrap_or("")),
            ("id", pol.id.as_str()),
            ("policy_type", pol.policy_type.as_deref().unwrap_or("")),
            ("description", pol.description.as_deref().unwrap_or("")),
        ];
        let nets: Vec<&str> = pol.networks.iter().map(|s| s.as_str()).collect();
        for n in &nets {
            fields.push(("network", *n));
        }
        let alts: Vec<&str> = pol
            .alternative_name_servers
            .iter()
            .map(|s| s.as_str())
            .collect();
        for a in &alts {
            fields.push(("name_server", *a));
        }
        let domains: Vec<&str> = pol.domains.iter().map(|s| s.as_str()).collect();
        for d in &domains {
            fields.push(("domain", *d));
        }
        if let Some((field, value, score)) = best_field_match(&q.pattern, q.mode, &fields) {
            let mut attrs = serde_json::Map::new();
            if let Some(t) = &pol.policy_type {
                attrs.insert("policy_type".into(), json!(t));
            }
            if !pol.networks.is_empty() {
                attrs.insert("networks".into(), json!(pol.networks));
            }
            if !pol.alternative_name_servers.is_empty() {
                attrs.insert(
                    "alternative_name_servers".into(),
                    json!(pol.alternative_name_servers),
                );
            }
            if !pol.domains.is_empty() {
                attrs.insert("domains".into(), json!(pol.domains));
            }
            result.hits.push(DiscoveryHit {
                kind: ResourceKind::DnsPolicy,
                cloud: inv.cloud,
                profile_id: Some(inv.profile_id.clone()),
                region: inv.region.clone(),
                name: pol.name.clone().unwrap_or_else(|| pol.id.clone()),
                id: Some(pol.id.clone()),
                matched_field: field,
                matched_value: value,
                score,
                attrs,
            });
        }
    }

    for link in &inv.vnet_links {
        if let Some((field, value, score)) = best_field_match(
            &q.pattern,
            q.mode,
            &[
                ("name", link.name.as_deref().unwrap_or("")),
                ("id", link.id.as_str()),
                ("zone_name", link.zone_name.as_str()),
                ("vnet_id", link.vnet_id.as_deref().unwrap_or("")),
            ],
        ) {
            let mut attrs = serde_json::Map::new();
            attrs.insert("zone_name".into(), json!(link.zone_name));
            if let Some(v) = &link.vnet_id {
                attrs.insert("vnet_id".into(), json!(v));
            }
            if let Some(r) = link.registration_enabled {
                attrs.insert("registration_enabled".into(), json!(r));
            }
            result.hits.push(DiscoveryHit {
                kind: ResourceKind::DnsVnetLink,
                cloud: inv.cloud,
                profile_id: Some(inv.profile_id.clone()),
                region: inv.region.clone(),
                name: link.name.clone().unwrap_or_else(|| link.id.clone()),
                id: Some(link.id.clone()),
                matched_field: field,
                matched_value: value,
                score,
                attrs,
            });
        }
    }

    for pr in &inv.private_resolvers {
        let mut fields = vec![
            ("name", pr.name.as_deref().unwrap_or("")),
            ("id", pr.id.as_str()),
            ("status", pr.status.as_deref().unwrap_or("")),
            ("vnet_id", pr.vnet_id.as_deref().unwrap_or("")),
            ("location", pr.location.as_deref().unwrap_or("")),
        ];
        let eps: Vec<&str> = pr.endpoints.iter().map(|s| s.as_str()).collect();
        for e in &eps {
            fields.push(("endpoint", *e));
        }
        if let Some((field, value, score)) = best_field_match(&q.pattern, q.mode, &fields) {
            let mut attrs = serde_json::Map::new();
            if let Some(v) = &pr.vnet_id {
                attrs.insert("vnet_id".into(), json!(v));
            }
            if !pr.endpoints.is_empty() {
                attrs.insert("endpoints".into(), json!(pr.endpoints));
            }
            if !pr.rulesets.is_empty() {
                attrs.insert("rulesets".into(), json!(pr.rulesets));
            }
            result.hits.push(DiscoveryHit {
                kind: ResourceKind::DnsPrivateResolver,
                cloud: inv.cloud,
                profile_id: Some(inv.profile_id.clone()),
                region: inv.region.clone().or(pr.location.clone()),
                name: pr.name.clone().unwrap_or_else(|| pr.id.clone()),
                id: Some(pr.id.clone()),
                matched_field: field,
                matched_value: value,
                score,
                attrs,
            });
        }
    }

    result.hits.truncate(q.limit);
    result.finalize()
}

fn match_resolver_endpoint(
    inv: &DnsResolverInventory,
    ep: &ResolverEndpointEntry,
    q: &PatternQuery,
    mode: MatchMode,
) -> Option<DiscoveryHit> {
    let name = ep.name.as_deref().unwrap_or("");
    let mut fields = vec![
        ("name", name),
        ("id", ep.id.as_str()),
        ("direction", ep.direction.as_str()),
        ("status", ep.status.as_deref().unwrap_or("")),
        ("vpc_id", ep.vpc_id.as_deref().unwrap_or("")),
    ];
    let subs: Vec<&str> = ep.subnet_ids.iter().map(|s| s.as_str()).collect();
    for s in &subs {
        fields.push(("subnet_id", *s));
    }
    let ips: Vec<&str> = ep.ip_addresses.iter().map(|s| s.as_str()).collect();
    for ip in &ips {
        fields.push(("ip", *ip));
    }
    let (field, value, score) = best_field_match(&q.pattern, mode, &fields)?;
    let mut attrs = serde_json::Map::new();
    attrs.insert("direction".into(), json!(ep.direction));
    if let Some(v) = &ep.vpc_id {
        attrs.insert("vpc_id".into(), json!(v));
    }
    if !ep.ip_addresses.is_empty() {
        attrs.insert("ip_addresses".into(), json!(ep.ip_addresses));
    }
    if !ep.subnet_ids.is_empty() {
        attrs.insert("subnet_ids".into(), json!(ep.subnet_ids));
    }
    Some(DiscoveryHit {
        kind: ResourceKind::DnsResolverEndpoint,
        cloud: inv.cloud,
        profile_id: Some(inv.profile_id.clone()),
        region: inv.region.clone(),
        name: ep.name.clone().unwrap_or_else(|| ep.id.clone()),
        id: Some(ep.id.clone()),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    })
}

fn match_resolver_rule(
    inv: &DnsResolverInventory,
    rule: &ResolverRuleEntry,
    q: &PatternQuery,
    mode: MatchMode,
) -> Option<DiscoveryHit> {
    let name = rule.name.as_deref().unwrap_or("");
    let mut fields = vec![
        ("name", name),
        ("id", rule.id.as_str()),
        ("domain_name", rule.domain_name.as_str()),
        ("rule_type", rule.rule_type.as_deref().unwrap_or("")),
        (
            "resolver_endpoint_id",
            rule.resolver_endpoint_id.as_deref().unwrap_or(""),
        ),
    ];
    let tips: Vec<&str> = rule.target_ips.iter().map(|s| s.as_str()).collect();
    for t in &tips {
        fields.push(("target_ip", *t));
    }
    let vpcs: Vec<&str> = rule.vpc_ids.iter().map(|s| s.as_str()).collect();
    for v in &vpcs {
        fields.push(("vpc_id", *v));
    }
    let (field, value, score) = best_field_match(&q.pattern, mode, &fields)?;
    let mut attrs = serde_json::Map::new();
    attrs.insert("domain_name".into(), json!(rule.domain_name));
    if let Some(t) = &rule.rule_type {
        attrs.insert("rule_type".into(), json!(t));
    }
    if !rule.target_ips.is_empty() {
        attrs.insert("target_ips".into(), json!(rule.target_ips));
    }
    if let Some(e) = &rule.resolver_endpoint_id {
        attrs.insert("resolver_endpoint_id".into(), json!(e));
    }
    Some(DiscoveryHit {
        kind: ResourceKind::DnsResolverRule,
        cloud: inv.cloud,
        profile_id: Some(inv.profile_id.clone()),
        region: inv.region.clone(),
        name: rule
            .name
            .clone()
            .unwrap_or_else(|| rule.domain_name.clone()),
        id: Some(rule.id.clone()),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    })
}

pub fn scan_network_inventory(inv: &NetworkInventory, q: &PatternQuery) -> DiscoveryResult {
    let mut result = DiscoveryResult::empty(
        &q.pattern,
        q.mode,
        format!(
            "network:{}:{}:{}",
            inv.cloud,
            inv.profile_id,
            inv.region.as_deref().unwrap_or("all")
        ),
    );

    // For network discovery, default partial name match also tries ip_or_cidr on CIDR fields.
    let modes = dual_modes(q.mode);

    for vpc in &inv.vpcs {
        for mode in &modes {
            if let Some(hit) = match_vpc(inv, vpc, q, *mode) {
                result.hits.push(hit);
                break;
            }
        }
    }
    for subnet in &inv.subnets {
        for mode in &modes {
            if let Some(hit) = match_subnet(inv, subnet, q, *mode) {
                result.hits.push(hit);
                break;
            }
        }
    }
    for addr in &inv.addresses {
        for mode in &modes {
            if let Some(hit) = match_address(inv, addr, q, *mode) {
                result.hits.push(hit);
                break;
            }
        }
    }
    for sg in &inv.security_groups {
        for mode in &modes {
            if let Some(hit) = match_security_group(inv, sg, q, *mode) {
                result.hits.push(hit);
                break;
            }
        }
    }
    for nacl in &inv.nacls {
        for mode in &modes {
            if let Some(hit) = match_nacl(inv, nacl, q, *mode) {
                result.hits.push(hit);
                break;
            }
        }
    }
    for rt in &inv.route_tables {
        for mode in &modes {
            if let Some(hit) = match_route_table(inv, rt, q, *mode) {
                result.hits.push(hit);
                break;
            }
        }
    }
    for route in &inv.routes {
        for mode in &modes {
            if let Some(hit) = match_route(inv, route, q, *mode) {
                result.hits.push(hit);
                break;
            }
        }
    }
    for func in &inv.functions {
        for mode in &modes {
            if let Some(hit) = match_function(inv, func, q, *mode) {
                result.hits.push(hit);
                break;
            }
        }
    }
    for svc in &inv.services {
        for mode in &modes {
            if let Some(hit) = match_network_service(inv, svc, q, *mode) {
                result.hits.push(hit);
                break;
            }
        }
    }

    result.hits.truncate(q.limit);
    result.finalize()
}

/// Map inventory `service_type` string → discovery ResourceKind.
pub fn service_type_to_kind(service_type: &str) -> ResourceKind {
    match service_type.to_ascii_lowercase().as_str() {
        "peering" | "vpc_peering" | "vnet_peering" | "network_peering" => ResourceKind::Peering,
        "transit_gateway" | "tgw" | "virtual_hub" | "ncc_hub" | "vwan" => {
            ResourceKind::TransitGateway
        }
        "vpn" | "vpn_connection" | "vpn_gateway" | "vpn_tunnel" | "client_vpn" => {
            ResourceKind::Vpn
        }
        "hybrid" | "direct_connect" | "dx" | "expressroute" | "interconnect" | "cross_cloud" => {
            ResourceKind::HybridConnection
        }
        "private_endpoint"
        | "vpc_endpoint"
        | "privatelink"
        | "private_service_connect"
        | "psc"
        | "private_link_service" => ResourceKind::PrivateEndpoint,
        "nat" | "nat_gateway" | "cloud_nat" => ResourceKind::NatGateway,
        "igw" | "internet_gateway" | "eigw" | "egress_only_internet_gateway" => {
            ResourceKind::InternetGateway
        }
        "share" | "network_share" | "ram" | "shared_vpc" | "host_project" => {
            ResourceKind::NetworkShare
        }
        "prefix_list" | "managed_prefix_list" | "ip_group" => ResourceKind::PrefixList,
        "load_balancer" | "elb" | "alb" | "nlb" | "gclb" | "application_gateway" => {
            ResourceKind::LoadBalancer
        }
        _ => ResourceKind::Other,
    }
}

fn match_network_service(
    inv: &NetworkInventory,
    svc: &NetworkServiceEntry,
    q: &PatternQuery,
    mode: MatchMode,
) -> Option<DiscoveryHit> {
    let name = svc.name.as_deref().unwrap_or("");
    let mut fields = vec![
        ("id", svc.id.as_str()),
        ("name", name),
        ("service_type", svc.service_type.as_str()),
        ("status", svc.status.as_deref().unwrap_or("")),
        ("vpc_id", svc.vpc_id.as_deref().unwrap_or("")),
        ("description", svc.description.as_deref().unwrap_or("")),
    ];
    let related: Vec<&str> = svc.related_ids.iter().map(|s| s.as_str()).collect();
    for r in &related {
        fields.push(("related", *r));
    }
    let cidrs: Vec<&str> = svc.cidrs.iter().map(|s| s.as_str()).collect();
    for c in &cidrs {
        fields.push(("cidr", *c));
    }
    let (field, value, score) = best_field_match(&q.pattern, mode, &fields)?;
    let mut attrs = serde_json::Map::new();
    attrs.insert("service_type".into(), json!(svc.service_type));
    if let Some(s) = &svc.status {
        attrs.insert("status".into(), json!(s));
    }
    if let Some(v) = &svc.vpc_id {
        attrs.insert("vpc_id".into(), json!(v));
    }
    if !svc.related_ids.is_empty() {
        attrs.insert("related_ids".into(), json!(svc.related_ids));
    }
    if !svc.cidrs.is_empty() {
        attrs.insert("cidrs".into(), json!(svc.cidrs));
    }
    if let Some(d) = &svc.description {
        attrs.insert("description".into(), json!(d));
    }
    Some(DiscoveryHit {
        kind: service_type_to_kind(&svc.service_type),
        cloud: inv.cloud,
        profile_id: Some(inv.profile_id.clone()),
        region: svc.region.clone().or_else(|| inv.region.clone()),
        name: if name.is_empty() {
            svc.id.clone()
        } else {
            name.to_string()
        },
        id: Some(svc.id.clone()),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    })
}

fn dual_modes(mode: MatchMode) -> Vec<MatchMode> {
    match mode {
        MatchMode::IpOrCidr => vec![MatchMode::IpOrCidr, MatchMode::Partial],
        MatchMode::Partial => vec![MatchMode::Partial, MatchMode::IpOrCidr],
        other => vec![other, MatchMode::IpOrCidr],
    }
}

fn match_vpc(
    inv: &NetworkInventory,
    vpc: &VpcEntry,
    q: &PatternQuery,
    mode: MatchMode,
) -> Option<DiscoveryHit> {
    let name = vpc.name.as_deref().unwrap_or("");
    let mut fields = vec![
        ("vpc_id", vpc.id.as_str()),
        ("name", name),
        ("cidr", vpc.cidr.as_str()),
    ];
    let secondary: Vec<&str> = vpc.secondary_cidrs.iter().map(|s| s.as_str()).collect();
    for s in &secondary {
        fields.push(("secondary_cidr", *s));
    }
    let (field, value, score) = best_field_match(&q.pattern, mode, &fields)?;
    let mut attrs = serde_json::Map::new();
    attrs.insert("cidr".into(), json!(vpc.cidr));
    if !vpc.secondary_cidrs.is_empty() {
        attrs.insert("secondary_cidrs".into(), json!(vpc.secondary_cidrs));
    }
    Some(DiscoveryHit {
        kind: ResourceKind::Vpc,
        cloud: inv.cloud,
        profile_id: Some(inv.profile_id.clone()),
        region: vpc.region.clone().or_else(|| inv.region.clone()),
        name: if name.is_empty() {
            vpc.id.clone()
        } else {
            name.to_string()
        },
        id: Some(vpc.id.clone()),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    })
}

fn match_subnet(
    inv: &NetworkInventory,
    subnet: &SubnetEntry,
    q: &PatternQuery,
    mode: MatchMode,
) -> Option<DiscoveryHit> {
    let name = subnet.name.as_deref().unwrap_or("");
    let fields = [
        ("subnet_id", subnet.id.as_str()),
        ("name", name),
        ("cidr", subnet.cidr.as_str()),
        ("vpc_id", subnet.vpc_id.as_str()),
    ];
    let (field, value, score) = best_field_match(&q.pattern, mode, &fields)?;
    let mut attrs = serde_json::Map::new();
    attrs.insert("cidr".into(), json!(subnet.cidr));
    attrs.insert("vpc_id".into(), json!(subnet.vpc_id));
    if let Some(az) = &subnet.az {
        attrs.insert("az".into(), json!(az));
    }
    Some(DiscoveryHit {
        kind: ResourceKind::Subnet,
        cloud: inv.cloud,
        profile_id: Some(inv.profile_id.clone()),
        region: subnet.region.clone().or_else(|| inv.region.clone()),
        name: if name.is_empty() {
            subnet.id.clone()
        } else {
            name.to_string()
        },
        id: Some(subnet.id.clone()),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    })
}

fn match_address(
    inv: &NetworkInventory,
    addr: &AddressEntry,
    q: &PatternQuery,
    mode: MatchMode,
) -> Option<DiscoveryHit> {
    let name = addr.name.as_deref().unwrap_or("");
    let id = addr.id.as_deref().unwrap_or("");
    let fields = [
        ("ip", addr.ip.as_str()),
        ("name", name),
        ("id", id),
    ];
    let (field, value, score) = best_field_match(&q.pattern, mode, &fields)?;
    let mut attrs = serde_json::Map::new();
    attrs.insert("ip".into(), json!(addr.ip));
    if let Some(v) = &addr.vpc_id {
        attrs.insert("vpc_id".into(), json!(v));
    }
    if let Some(s) = &addr.subnet_id {
        attrs.insert("subnet_id".into(), json!(s));
    }
    if let Some(k) = &addr.kind {
        attrs.insert("kind".into(), json!(k));
    }
    Some(DiscoveryHit {
        kind: ResourceKind::IpAddress,
        cloud: inv.cloud,
        profile_id: Some(inv.profile_id.clone()),
        region: addr.region.clone().or_else(|| inv.region.clone()),
        name: if name.is_empty() {
            addr.ip.clone()
        } else {
            name.to_string()
        },
        id: addr.id.clone(),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    })
}

fn match_security_group(
    inv: &NetworkInventory,
    sg: &SecurityGroupEntry,
    q: &PatternQuery,
    mode: MatchMode,
) -> Option<DiscoveryHit> {
    let name = sg.name.as_deref().unwrap_or("");
    let fields = [
        ("id", sg.id.as_str()),
        ("name", name),
        ("description", sg.description.as_deref().unwrap_or("")),
        ("vpc_id", sg.vpc_id.as_deref().unwrap_or("")),
    ];
    let (field, value, score) = best_field_match(&q.pattern, mode, &fields)?;
    let mut attrs = serde_json::Map::new();
    if let Some(v) = &sg.vpc_id {
        attrs.insert("vpc_id".into(), json!(v));
    }
    if let Some(d) = &sg.description {
        attrs.insert("description".into(), json!(d));
    }
    Some(DiscoveryHit {
        kind: ResourceKind::SecurityGroup,
        cloud: inv.cloud,
        profile_id: Some(inv.profile_id.clone()),
        region: sg.region.clone().or_else(|| inv.region.clone()),
        name: if name.is_empty() {
            sg.id.clone()
        } else {
            name.to_string()
        },
        id: Some(sg.id.clone()),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    })
}

fn match_nacl(
    inv: &NetworkInventory,
    nacl: &NaclEntry,
    q: &PatternQuery,
    mode: MatchMode,
) -> Option<DiscoveryHit> {
    let name = nacl.name.as_deref().unwrap_or("");
    let fields = [
        ("id", nacl.id.as_str()),
        ("name", name),
        ("vpc_id", nacl.vpc_id.as_deref().unwrap_or("")),
    ];
    let (field, value, score) = best_field_match(&q.pattern, mode, &fields)?;
    let mut attrs = serde_json::Map::new();
    if let Some(v) = &nacl.vpc_id {
        attrs.insert("vpc_id".into(), json!(v));
    }
    if let Some(d) = nacl.is_default {
        attrs.insert("is_default".into(), json!(d));
    }
    Some(DiscoveryHit {
        kind: ResourceKind::Nacl,
        cloud: inv.cloud,
        profile_id: Some(inv.profile_id.clone()),
        region: nacl.region.clone().or_else(|| inv.region.clone()),
        name: if name.is_empty() {
            nacl.id.clone()
        } else {
            name.to_string()
        },
        id: Some(nacl.id.clone()),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    })
}

fn match_route_table(
    inv: &NetworkInventory,
    rt: &RouteTableEntry,
    q: &PatternQuery,
    mode: MatchMode,
) -> Option<DiscoveryHit> {
    let name = rt.name.as_deref().unwrap_or("");
    let mut fields = vec![
        ("id", rt.id.as_str()),
        ("name", name),
        ("vpc_id", rt.vpc_id.as_deref().unwrap_or("")),
    ];
    let dests: Vec<&str> = rt.destinations.iter().map(|s| s.as_str()).collect();
    for d in &dests {
        fields.push(("destination", *d));
    }
    let targets: Vec<&str> = rt.targets.iter().map(|s| s.as_str()).collect();
    for t in &targets {
        fields.push(("target", *t));
    }
    let (field, value, score) = best_field_match(&q.pattern, mode, &fields)?;
    let mut attrs = serde_json::Map::new();
    if let Some(v) = &rt.vpc_id {
        attrs.insert("vpc_id".into(), json!(v));
    }
    if !rt.destinations.is_empty() {
        attrs.insert("destinations".into(), json!(rt.destinations));
    }
    if !rt.targets.is_empty() {
        attrs.insert("targets".into(), json!(rt.targets));
    }
    Some(DiscoveryHit {
        kind: ResourceKind::RouteTable,
        cloud: inv.cloud,
        profile_id: Some(inv.profile_id.clone()),
        region: rt.region.clone().or_else(|| inv.region.clone()),
        name: if name.is_empty() {
            rt.id.clone()
        } else {
            name.to_string()
        },
        id: Some(rt.id.clone()),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    })
}

fn match_route(
    inv: &NetworkInventory,
    route: &RouteEntry,
    q: &PatternQuery,
    mode: MatchMode,
) -> Option<DiscoveryHit> {
    let name = route.name.as_deref().unwrap_or("");
    let fields = [
        ("id", route.id.as_str()),
        ("name", name),
        ("destination", route.destination.as_str()),
        ("target", route.target.as_deref().unwrap_or("")),
        ("route_table_id", route.route_table_id.as_str()),
        ("vpc_id", route.vpc_id.as_deref().unwrap_or("")),
    ];
    let (field, value, score) = best_field_match(&q.pattern, mode, &fields)?;
    let mut attrs = serde_json::Map::new();
    attrs.insert("destination".into(), json!(route.destination));
    attrs.insert("route_table_id".into(), json!(route.route_table_id));
    if let Some(t) = &route.target {
        attrs.insert("target".into(), json!(t));
    }
    if let Some(v) = &route.vpc_id {
        attrs.insert("vpc_id".into(), json!(v));
    }
    Some(DiscoveryHit {
        kind: ResourceKind::Route,
        cloud: inv.cloud,
        profile_id: Some(inv.profile_id.clone()),
        region: route.region.clone().or_else(|| inv.region.clone()),
        name: if name.is_empty() {
            route.destination.clone()
        } else {
            name.to_string()
        },
        id: Some(route.id.clone()),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    })
}

fn match_function(
    inv: &NetworkInventory,
    func: &FunctionEntry,
    q: &PatternQuery,
    mode: MatchMode,
) -> Option<DiscoveryHit> {
    let name = func.name.as_deref().unwrap_or("");
    let fields = [
        ("id", func.id.as_str()),
        ("name", name),
        ("runtime", func.runtime.as_deref().unwrap_or("")),
        ("vpc_id", func.vpc_id.as_deref().unwrap_or("")),
        ("arn", func.arn_or_url.as_deref().unwrap_or("")),
    ];
    let (field, value, score) = best_field_match(&q.pattern, mode, &fields)?;
    let mut attrs = serde_json::Map::new();
    if let Some(r) = &func.runtime {
        attrs.insert("runtime".into(), json!(r));
    }
    if let Some(v) = &func.vpc_id {
        attrs.insert("vpc_id".into(), json!(v));
    }
    if let Some(a) = &func.arn_or_url {
        attrs.insert("arn_or_url".into(), json!(a));
    }
    Some(DiscoveryHit {
        kind: ResourceKind::Function,
        cloud: inv.cloud,
        profile_id: Some(inv.profile_id.clone()),
        region: func.region.clone().or_else(|| inv.region.clone()),
        name: if name.is_empty() {
            func.id.clone()
        } else {
            name.to_string()
        },
        id: Some(func.id.clone()),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    })
}

pub fn scan_k8s_inventory(inv: &K8sInventory, q: &PatternQuery) -> DiscoveryResult {
    let scope = format!(
        "k8s:{}",
        inv.context
            .as_deref()
            .or(inv.profile_id.as_deref())
            .unwrap_or("default")
    );
    let mut result = DiscoveryResult::empty(&q.pattern, q.mode, scope);

    for res in &inv.resources {
        if let Some(hit) = match_k8s(inv, res, q) {
            result.hits.push(hit);
        }
        if result.hits.len() >= q.limit {
            break;
        }
    }
    result.hits.truncate(q.limit);
    result.finalize()
}

fn match_k8s(
    inv: &K8sInventory,
    res: &K8sResourceEntry,
    q: &PatternQuery,
) -> Option<DiscoveryHit> {
    let ns = res.namespace.as_deref().unwrap_or("");
    let mut owned: Vec<(String, String)> = vec![
        ("name".into(), res.name.clone()),
        ("kind".into(), res.kind.clone()),
        ("namespace".into(), ns.to_string()),
    ];
    for (i, lab) in res.labels.iter().enumerate() {
        owned.push((format!("label_{i}"), lab.clone()));
    }
    for (i, ip) in res.ips.iter().enumerate() {
        owned.push((format!("ip_{i}"), ip.clone()));
    }
    for (i, e) in res.extra.iter().enumerate() {
        owned.push((format!("extra_{i}"), e.clone()));
    }
    let fields: Vec<(&str, &str)> = owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    // Try query mode, and also ip_or_cidr for IP fields when partial.
    let mut best = best_field_match(&q.pattern, q.mode, &fields);
    if best.is_none() && q.mode == MatchMode::Partial {
        best = best_field_match(&q.pattern, MatchMode::IpOrCidr, &fields);
    }
    let (field, value, score) = best?;

    let kind = map_k8s_kind(&res.kind);
    let mut attrs = serde_json::Map::new();
    if let Some(ns) = &res.namespace {
        attrs.insert("namespace".into(), json!(ns));
    }
    attrs.insert("k8s_kind".into(), json!(res.kind));
    if !res.ips.is_empty() {
        attrs.insert("ips".into(), json!(res.ips));
    }
    if !res.labels.is_empty() {
        attrs.insert("labels".into(), json!(res.labels));
    }

    Some(DiscoveryHit {
        kind,
        cloud: Cloud::K8s,
        profile_id: inv.profile_id.clone(),
        region: inv.context.clone(),
        name: res.name.clone(),
        id: Some(format!(
            "{}/{}/{}",
            res.kind,
            res.namespace.as_deref().unwrap_or("cluster"),
            res.name
        )),
        matched_field: field,
        matched_value: value,
        score,
        attrs,
    })
}

fn map_k8s_kind(kind: &str) -> ResourceKind {
    match kind.to_ascii_lowercase().as_str() {
        "namespace" | "ns" => ResourceKind::K8sNamespace,
        "pod" | "pods" | "po" => ResourceKind::K8sPod,
        "service" | "services" | "svc" => ResourceKind::K8sService,
        "deployment" | "deployments" | "deploy" => ResourceKind::K8sDeployment,
        "ingress" | "ingresses" | "ing" => ResourceKind::K8sIngress,
        "configmap" | "configmaps" | "cm" => ResourceKind::K8sConfigMap,
        "secret" | "secrets" => ResourceKind::K8sSecret,
        "node" | "nodes" => ResourceKind::K8sNode,
        "networkpolicy" | "networkpolicies" | "netpol" => ResourceKind::K8sOther,
        "endpointslice" | "endpointslices" | "endpoints" | "endpoint" => ResourceKind::K8sService,
        _ => ResourceKind::K8sOther,
    }
}

/// Public DNS probe (system resolver) — finds where a name resolves on the public Internet.
pub struct PublicDnsProbe;

impl PublicDnsProbe {
    pub async fn resolve_name(name: &str) -> Vec<DiscoveryHit> {
        let mut hits = Vec::new();
        let host = name.trim_end_matches('.').to_string();
        // lookup_host needs host:port
        let target = format!("{host}:0");
        match tokio::net::lookup_host(&target).await {
            Ok(iter) => {
                let mut ips = Vec::new();
                for addr in iter {
                    ips.push(addr.ip().to_string());
                }
                ips.sort();
                ips.dedup();
                if !ips.is_empty() {
                    let mut attrs = serde_json::Map::new();
                    attrs.insert("values".into(), json!(ips));
                    attrs.insert("scope".into(), json!("public_system_resolver"));
                    hits.push(DiscoveryHit {
                        kind: ResourceKind::DnsRecord,
                        cloud: Cloud::Multi,
                        profile_id: None,
                        region: None,
                        name: host.clone(),
                        id: None,
                        matched_field: "public_a_aaaa".into(),
                        matched_value: ips.join(","),
                        score: 90,
                        attrs,
                    });
                }
            }
            Err(_) => {}
        }

        // FQDN partial: if pattern is partial, we only probe full names (caller decides).
        let _ = match_text;
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::*;

    fn sample_dns() -> DnsInventory {
        DnsInventory {
            profile_id: "aws-prod".into(),
            cloud: Cloud::Aws,
            zones: vec![DnsZoneEntry {
                id: "Z1".into(),
                name: "prod.internal.".into(),
                private: true,
                vpc_or_network_ids: vec!["vpc-abc".into()],
                region: Some("us-east-1".into()),
                records: vec![DnsRecordEntry {
                    name: "api.prod.internal.".into(),
                    record_type: "A".into(),
                    values: vec!["10.0.4.12".into()],
                    ttl: Some(60),
                }],
            }],
        }
    }

    #[test]
    fn dns_partial_finds_record() {
        let inv = sample_dns();
        let q = PatternQuery {
            pattern: "api.prod".into(),
            mode: MatchMode::Partial,
            profile_id: None,
            region: None,
            limit: 20,
        };
        let r = scan_dns_inventory(&inv, &q);
        assert!(r.hit_count >= 1);
        assert!(r.hits.iter().any(|h| h.kind == ResourceKind::DnsRecord));
    }

    #[test]
    fn subnet_partial_cidr() {
        let inv = NetworkInventory {
            profile_id: "aws-prod".into(),
            cloud: Cloud::Aws,
            region: Some("us-east-1".into()),
            vpcs: vec![VpcEntry {
                id: "vpc-1".into(),
                name: Some("main".into()),
                cidr: "10.0.0.0/16".into(),
                secondary_cidrs: vec![],
                region: Some("us-east-1".into()),
            }],
            subnets: vec![SubnetEntry {
                id: "subnet-1".into(),
                name: Some("app-a".into()),
                cidr: "10.0.4.0/24".into(),
                vpc_id: "vpc-1".into(),
                az: Some("us-east-1a".into()),
                region: Some("us-east-1".into()),
            }],
            addresses: vec![],
            security_groups: vec![SecurityGroupEntry {
                id: "sg-app".into(),
                name: Some("app-web".into()),
                description: Some("web tier".into()),
                vpc_id: Some("vpc-1".into()),
                region: Some("us-east-1".into()),
            }],
            nacls: vec![NaclEntry {
                id: "acl-1".into(),
                name: Some("private-nacl".into()),
                vpc_id: Some("vpc-1".into()),
                is_default: Some(false),
                region: Some("us-east-1".into()),
            }],
            route_tables: vec![RouteTableEntry {
                id: "rtb-1".into(),
                name: Some("public-rt".into()),
                vpc_id: Some("vpc-1".into()),
                region: Some("us-east-1".into()),
                destinations: vec!["0.0.0.0/0".into(), "10.0.0.0/16".into()],
                targets: vec!["igw-1".into()],
            }],
            routes: vec![RouteEntry {
                id: "rtb-1:0.0.0.0/0".into(),
                name: Some("default".into()),
                route_table_id: "rtb-1".into(),
                destination: "0.0.0.0/0".into(),
                target: Some("igw-1".into()),
                vpc_id: Some("vpc-1".into()),
                region: Some("us-east-1".into()),
            }],
            functions: vec![FunctionEntry {
                id: "arn:aws:lambda:us-east-1:1:function:api-handler".into(),
                name: Some("api-handler".into()),
                runtime: Some("python3.12".into()),
                region: Some("us-east-1".into()),
                vpc_id: Some("vpc-1".into()),
                arn_or_url: Some("arn:aws:lambda:us-east-1:1:function:api-handler".into()),
            }],
            services: vec![],
        };
        let q = PatternQuery {
            pattern: "10.0.4".into(),
            mode: MatchMode::Partial,
            profile_id: None,
            region: None,
            limit: 20,
        };
        let r = scan_network_inventory(&inv, &q);
        assert!(r.hits.iter().any(|h| h.kind == ResourceKind::Subnet));
    }

    #[test]
    fn pattern_hits_sg_nacl_rt_route_function() {
        let inv = NetworkInventory {
            profile_id: "aws-prod".into(),
            cloud: Cloud::Aws,
            region: Some("us-east-1".into()),
            vpcs: vec![],
            subnets: vec![],
            addresses: vec![],
            security_groups: vec![SecurityGroupEntry {
                id: "sg-app".into(),
                name: Some("app-web".into()),
                description: Some("web".into()),
                vpc_id: None,
                region: None,
            }],
            nacls: vec![NaclEntry {
                id: "acl-1".into(),
                name: Some("private-nacl".into()),
                vpc_id: None,
                is_default: None,
                region: None,
            }],
            route_tables: vec![RouteTableEntry {
                id: "rtb-1".into(),
                name: Some("public-rt".into()),
                vpc_id: None,
                region: None,
                destinations: vec!["0.0.0.0/0".into()],
                targets: vec![],
            }],
            routes: vec![RouteEntry {
                id: "rtb-1:10.1.0.0/16".into(),
                name: None,
                route_table_id: "rtb-1".into(),
                destination: "10.1.0.0/16".into(),
                target: Some("pcx-1".into()),
                vpc_id: None,
                region: None,
            }],
            functions: vec![FunctionEntry {
                id: "fn-1".into(),
                name: Some("api-handler".into()),
                runtime: Some("nodejs20.x".into()),
                region: None,
                vpc_id: None,
                arn_or_url: None,
            }],
            services: vec![
                NetworkServiceEntry {
                    id: "pcx-1".into(),
                    name: Some("app-to-shared".into()),
                    service_type: "peering".into(),
                    status: Some("active".into()),
                    vpc_id: Some("vpc-1".into()),
                    related_ids: vec!["vpc-2".into()],
                    cidrs: vec!["10.2.0.0/16".into()],
                    region: None,
                    description: Some("vpc peering".into()),
                },
                NetworkServiceEntry {
                    id: "tgw-1".into(),
                    name: Some("hub-tgw".into()),
                    service_type: "transit_gateway".into(),
                    status: Some("available".into()),
                    vpc_id: None,
                    related_ids: vec![],
                    cidrs: vec![],
                    region: None,
                    description: None,
                },
            ],
        };
        for (pat, kind) in [
            ("app-web", ResourceKind::SecurityGroup),
            ("private-nacl", ResourceKind::Nacl),
            ("public-rt", ResourceKind::RouteTable),
            ("10.1.0", ResourceKind::Route),
            ("api-handler", ResourceKind::Function),
            ("app-to-shared", ResourceKind::Peering),
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
