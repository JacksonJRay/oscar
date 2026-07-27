//! Run pattern matchers over DNS / network / k8s inventories.

use crate::inventory::{
    AddressEntry, DnsInventory, DnsRecordEntry, DnsResolverInventory, DnsZoneEntry, K8sInventory,
    K8sResourceEntry, NetworkInventory, ResolverEndpointEntry, ResolverRuleEntry, SubnetEntry,
    VpcEntry,
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

    for zone in &inv.zones {
        if let Some((field, value, score)) = best_field_match(
            &q.pattern,
            q.mode,
            &[
                ("zone_name", zone.name.as_str()),
                ("zone_id", zone.id.as_str()),
            ],
        ) {
            result.hits.push(hit_dns_zone(inv, zone, field, value, score));
        }

        // Also allow IP mode against record values inside the zone.
        for rec in &zone.records {
            push_dns_record_hits(&mut result, inv, zone, rec, q);
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
) {
    let mut fields: Vec<(&str, String)> = vec![
        ("record_name", rec.name.clone()),
        ("record_type", rec.record_type.clone()),
        ("zone_name", zone.name.clone()),
    ];
    for (i, v) in rec.values.iter().enumerate() {
        fields.push((
            if i == 0 { "record_value" } else { "record_value" },
            v.clone(),
        ));
    }
    let field_refs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (*k, v.as_str()))
        .collect();

    // Prefer name matching unless mode is IP-focused.
    let mode = q.mode;
    if let Some((field, value, mut score)) = best_field_match(&q.pattern, mode, &field_refs) {
        // Boost when both name and zone align with a FQDN-ish query.
        if rec.name.to_ascii_lowercase().contains(&q.pattern.to_ascii_lowercase()) {
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

    result.hits.truncate(q.limit);
    result.finalize()
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
}
