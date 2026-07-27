//! Pattern-based discovery types shared by DNS, network, and Kubernetes tools.
//!
//! These go beyond native list/get APIs: partial string match, glob, CIDR/IP
//! containment, and scored ranked hits so the agent can find resources with
//! short, high-accuracy tool calls instead of long exploratory queries.

use crate::types::Cloud;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

/// How a search pattern is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    /// Case-insensitive substring (default for names).
    #[default]
    Partial,
    /// Match from the start of the string.
    Prefix,
    /// Match at the end of the string.
    Suffix,
    /// Exact match (case-insensitive).
    Exact,
    /// Simple glob: `*` any sequence, `?` single char (case-insensitive).
    Glob,
    /// IP/CIDR semantics: pattern may be IP fragment, full IP, or CIDR.
    /// Subject may be IP, CIDR, or free text containing an IP.
    IpOrCidr,
}

impl MatchMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "partial" | "contains" | "substring" => Some(MatchMode::Partial),
            "prefix" | "starts_with" | "startswith" => Some(MatchMode::Prefix),
            "suffix" | "ends_with" | "endswith" => Some(MatchMode::Suffix),
            "exact" | "eq" | "=" => Some(MatchMode::Exact),
            "glob" | "wildcard" => Some(MatchMode::Glob),
            "ip" | "cidr" | "ip_or_cidr" | "network" => Some(MatchMode::IpOrCidr),
            _ => None,
        }
    }
}

impl fmt::Display for MatchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            MatchMode::Partial => "partial",
            MatchMode::Prefix => "prefix",
            MatchMode::Suffix => "suffix",
            MatchMode::Exact => "exact",
            MatchMode::Glob => "glob",
            MatchMode::IpOrCidr => "ip_or_cidr",
        };
        write!(f, "{s}")
    }
}

/// Kind of resource returned by discovery tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    DnsZone,
    DnsRecord,
    /// Route 53 Resolver inbound/outbound endpoint (or CSP equivalent).
    DnsResolverEndpoint,
    /// Route 53 Resolver forwarding rule (or CSP equivalent).
    DnsResolverRule,
    /// DNS Firewall rule group.
    DnsFirewallRuleGroup,
    /// Resolver / DNS query logging configuration.
    DnsQueryLogConfig,
    /// AWS Route 53 Profile (or multi-account DNS share object).
    DnsProfile,
    /// DNS policy (GCP Cloud DNS policy, response policy, etc.).
    DnsPolicy,
    /// Private DNS ↔ VNet/VPC link association.
    DnsVnetLink,
    /// CSP private DNS resolver instance (Azure DNS Private Resolver, …).
    DnsPrivateResolver,
    Vpc,
    Subnet,
    IpAddress,
    SecurityGroup,
    RouteTable,
    LoadBalancer,
    K8sNamespace,
    K8sPod,
    K8sService,
    K8sDeployment,
    K8sIngress,
    K8sConfigMap,
    K8sSecret,
    K8sNode,
    K8sOther,
    /// IAM / identity / access control objects
    IamUser,
    IamGroup,
    IamRole,
    IamPolicy,
    IamServiceAccount,
    IamBinding,
    IamRoleAssignment,
    Other,
}

impl fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ResourceKind::DnsZone => "dns_zone",
            ResourceKind::DnsRecord => "dns_record",
            ResourceKind::DnsResolverEndpoint => "dns_resolver_endpoint",
            ResourceKind::DnsResolverRule => "dns_resolver_rule",
            ResourceKind::DnsFirewallRuleGroup => "dns_firewall_rule_group",
            ResourceKind::DnsQueryLogConfig => "dns_query_log_config",
            ResourceKind::DnsProfile => "dns_profile",
            ResourceKind::DnsPolicy => "dns_policy",
            ResourceKind::DnsVnetLink => "dns_vnet_link",
            ResourceKind::DnsPrivateResolver => "dns_private_resolver",
            ResourceKind::Vpc => "vpc",
            ResourceKind::Subnet => "subnet",
            ResourceKind::IpAddress => "ip_address",
            ResourceKind::SecurityGroup => "security_group",
            ResourceKind::RouteTable => "route_table",
            ResourceKind::LoadBalancer => "load_balancer",
            ResourceKind::K8sNamespace => "k8s_namespace",
            ResourceKind::K8sPod => "k8s_pod",
            ResourceKind::K8sService => "k8s_service",
            ResourceKind::K8sDeployment => "k8s_deployment",
            ResourceKind::K8sIngress => "k8s_ingress",
            ResourceKind::K8sConfigMap => "k8s_configmap",
            ResourceKind::K8sSecret => "k8s_secret",
            ResourceKind::K8sNode => "k8s_node",
            ResourceKind::K8sOther => "k8s_other",
            ResourceKind::IamUser => "iam_user",
            ResourceKind::IamGroup => "iam_group",
            ResourceKind::IamRole => "iam_role",
            ResourceKind::IamPolicy => "iam_policy",
            ResourceKind::IamServiceAccount => "iam_service_account",
            ResourceKind::IamBinding => "iam_binding",
            ResourceKind::IamRoleAssignment => "iam_role_assignment",
            ResourceKind::Other => "other",
        };
        write!(f, "{s}")
    }
}

/// Single ranked discovery hit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryHit {
    pub kind: ResourceKind,
    pub cloud: Cloud,
    pub profile_id: Option<String>,
    pub region: Option<String>,
    /// Human-readable name (zone name, subnet name, pod name, …).
    pub name: String,
    /// Provider resource id when known.
    pub id: Option<String>,
    /// Field that matched (e.g. `zone_name`, `cidr`, `record_name`, `pod_ip`).
    pub matched_field: String,
    /// Matched value excerpt.
    pub matched_value: String,
    /// 0–100 relevance (higher is better).
    pub score: u32,
    /// Extra structured context (zone private?, VPC id, namespace, …).
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub attrs: serde_json::Map<String, serde_json::Value>,
}

/// Result envelope for all pattern-search tools.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryResult {
    pub pattern: String,
    pub mode: MatchMode,
    pub query_scope: String,
    pub hit_count: usize,
    pub hits: Vec<DiscoveryHit>,
    /// True when inventory was incomplete (e.g. live API not wired / auth missing for some accounts).
    pub partial: bool,
    pub notes: Vec<String>,
}

impl DiscoveryResult {
    pub fn empty(pattern: impl Into<String>, mode: MatchMode, scope: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            mode,
            query_scope: scope.into(),
            hit_count: 0,
            hits: vec![],
            partial: false,
            notes: vec![],
        }
    }

    pub fn finalize(mut self) -> Self {
        self.hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));
        self.hit_count = self.hits.len();
        self
    }
}

/// Common args parsed from tool JSON.
#[derive(Debug, Clone)]
pub struct PatternQuery {
    pub pattern: String,
    pub mode: MatchMode,
    pub profile_id: Option<String>,
    pub region: Option<String>,
    pub limit: usize,
}

impl PatternQuery {
    pub fn from_args(args: &serde_json::Value) -> Result<Self, String> {
        let pattern = args
            .get("pattern")
            .or_else(|| args.get("query"))
            .or_else(|| args.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if pattern.is_empty() {
            return Err("pattern is required (partial name, glob, IP, or CIDR)".into());
        }
        let mode = args
            .get("mode")
            .and_then(|v| v.as_str())
            .and_then(MatchMode::parse)
            .unwrap_or_else(|| infer_mode(&pattern));
        let profile_id = args
            .get("profile_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let region = args
            .get("region")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(50)
            .clamp(1, 500) as usize;
        Ok(Self {
            pattern,
            mode,
            profile_id,
            region,
            limit,
        })
    }
}

fn infer_mode(pattern: &str) -> MatchMode {
    if pattern.contains('*') || pattern.contains('?') {
        return MatchMode::Glob;
    }
    if pattern.contains('/') && pattern.parse::<ipnet_lite::IpNetLite>().is_ok() {
        return MatchMode::IpOrCidr;
    }
    if pattern.parse::<IpAddr>().is_ok() || looks_like_ip_fragment(pattern) {
        return MatchMode::IpOrCidr;
    }
    MatchMode::Partial
}

fn looks_like_ip_fragment(s: &str) -> bool {
    // e.g. "10.0.", "172.16.4", "2001:db8"
    let dots = s.matches('.').count();
    let colons = s.matches(':').count();
    if dots >= 1 && s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return true;
    }
    if colons >= 1 && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
        return true;
    }
    false
}

/// Score a string field against a pattern. Returns None if no match.
pub fn match_text(pattern: &str, mode: MatchMode, field: &str, value: &str) -> Option<u32> {
    let p = pattern.to_ascii_lowercase();
    let v = value.to_ascii_lowercase();
    match mode {
        MatchMode::Exact => {
            if p == v {
                Some(100)
            } else {
                None
            }
        }
        MatchMode::Prefix => {
            if v.starts_with(&p) {
                Some(score_len_ratio(&p, &v, 90))
            } else {
                None
            }
        }
        MatchMode::Suffix => {
            if v.ends_with(&p) {
                Some(score_len_ratio(&p, &v, 85))
            } else {
                None
            }
        }
        MatchMode::Partial => {
            if let Some(idx) = v.find(&p) {
                let base = if idx == 0 { 80 } else { 60 };
                Some(score_len_ratio(&p, &v, base))
            } else {
                None
            }
        }
        MatchMode::Glob => {
            if glob_match(&p, &v) {
                Some(75)
            } else {
                None
            }
        }
        MatchMode::IpOrCidr => match_ip_or_cidr(pattern, value).map(|s| {
            // still attach field name weight via unused field for API symmetry
            let _ = field;
            s
        }),
    }
    .map(|s| {
        let _ = field;
        s
    })
}

fn score_len_ratio(pattern: &str, value: &str, base: u32) -> u32 {
    if value.is_empty() {
        return base;
    }
    let ratio = pattern.len() as f32 / value.len() as f32;
    let bonus = (ratio * 20.0).round() as u32;
    (base + bonus).min(100)
}

/// Simple case-folded glob: `*` and `?` only.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    glob_match_rec(pattern.as_bytes(), value.as_bytes())
}

fn glob_match_rec(pat: &[u8], val: &[u8]) -> bool {
    let mut pi = 0;
    let mut vi = 0;
    let mut star_p: Option<usize> = None;
    let mut star_v: usize = 0;
    while vi < val.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == val[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star_p = Some(pi);
            star_v = vi;
            pi += 1;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_v += 1;
            vi = star_v;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Match IP fragment, full IP, or CIDR against a subject that is IP, CIDR, or text containing them.
pub fn match_ip_or_cidr(pattern: &str, subject: &str) -> Option<u32> {
    let pat = pattern.trim();
    let sub = subject.trim();

    // Exact IP
    if let (Ok(p), Ok(s)) = (pat.parse::<IpAddr>(), sub.parse::<IpAddr>()) {
        return if p == s { Some(100) } else { None };
    }

    // Pattern CIDR contains subject IP
    if let Ok(net) = pat.parse::<ipnet_lite::IpNetLite>() {
        if let Ok(ip) = sub.parse::<IpAddr>() {
            return if net.contains(ip) { Some(95) } else { None };
        }
        if let Ok(other) = sub.parse::<ipnet_lite::IpNetLite>() {
            return if net.contains_net(&other) || other.contains_net(&net) || nets_overlap(&net, &other)
            {
                Some(90)
            } else {
                None
            };
        }
    }

    // Subject CIDR contains pattern IP
    if let Ok(ip) = pat.parse::<IpAddr>() {
        if let Ok(net) = sub.parse::<ipnet_lite::IpNetLite>() {
            return if net.contains(ip) { Some(95) } else { None };
        }
    }

    // Partial IP text (e.g. pattern "10.0.4" in "10.0.4.0/24" or "eni … 10.0.4.12")
    let p = pat.to_ascii_lowercase();
    let s = sub.to_ascii_lowercase();
    if s.contains(&p) {
        return Some(score_len_ratio(&p, &s, 70));
    }
    None
}

fn nets_overlap(a: &ipnet_lite::IpNetLite, b: &ipnet_lite::IpNetLite) -> bool {
    a.contains_net(b) || b.contains_net(a) || a.contains(b.network()) || b.contains(a.network())
}

/// Minimal IP network helper so we don't pull a heavy crate for discovery.
pub mod ipnet_lite {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[derive(Debug, Clone, Copy)]
    pub struct IpNetLite {
        pub addr: IpAddr,
        pub prefix: u8,
    }

    impl std::str::FromStr for IpNetLite {
        type Err = ();
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let (ip_s, pref_s) = s.split_once('/').ok_or(())?;
            let addr: IpAddr = ip_s.parse().map_err(|_| ())?;
            let prefix: u8 = pref_s.parse().map_err(|_| ())?;
            match addr {
                IpAddr::V4(_) if prefix > 32 => return Err(()),
                IpAddr::V6(_) if prefix > 128 => return Err(()),
                _ => {}
            }
            Ok(IpNetLite { addr, prefix })
        }
    }

    impl IpNetLite {
        pub fn network(&self) -> IpAddr {
            match self.addr {
                IpAddr::V4(ip) => IpAddr::V4(mask_v4(ip, self.prefix)),
                IpAddr::V6(ip) => IpAddr::V6(mask_v6(ip, self.prefix)),
            }
        }

        pub fn contains(&self, ip: IpAddr) -> bool {
            match (self.addr, ip) {
                (IpAddr::V4(_), IpAddr::V4(ip)) => {
                    let net = match self.network() {
                        IpAddr::V4(n) => n,
                        _ => return false,
                    };
                    mask_v4(ip, self.prefix) == net
                }
                (IpAddr::V6(_), IpAddr::V6(ip)) => {
                    let net = match self.network() {
                        IpAddr::V6(n) => n,
                        _ => return false,
                    };
                    mask_v6(ip, self.prefix) == net
                }
                _ => false,
            }
        }

        pub fn contains_net(&self, other: &IpNetLite) -> bool {
            // other is fully inside self if network and broadcast-ish last of other in self
            // Approximate: other.network in self and other.prefix >= self.prefix
            other.prefix >= self.prefix && self.contains(other.network())
        }
    }

    fn mask_v4(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
        if prefix == 0 {
            return Ipv4Addr::UNSPECIFIED;
        }
        let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
        Ipv4Addr::from(u32::from(ip) & mask)
    }

    fn mask_v6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
        let segs = ip.segments();
        let mut out = [0u16; 8];
        let mut bits = prefix as i32;
        for i in 0..8 {
            if bits >= 16 {
                out[i] = segs[i];
                bits -= 16;
            } else if bits > 0 {
                let mask = 0xffffu16 << (16 - bits);
                out[i] = segs[i] & mask;
                bits = 0;
            } else {
                out[i] = 0;
            }
        }
        Ipv6Addr::from(out)
    }
}

/// Try multiple candidate fields; return best score + which field matched.
pub fn best_field_match(
    pattern: &str,
    mode: MatchMode,
    fields: &[(&str, &str)],
) -> Option<(String, String, u32)> {
    let mut best: Option<(String, String, u32)> = None;
    for (field, value) in fields {
        if value.is_empty() {
            continue;
        }
        if let Some(score) = match_text(pattern, mode, field, value) {
            let cand = ((*field).to_string(), (*value).to_string(), score);
            if best.as_ref().map(|b| b.2).unwrap_or(0) < score {
                best = Some(cand);
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_dns_name() {
        let s = match_text("api", MatchMode::Partial, "name", "api.prod.internal").unwrap();
        assert!(s >= 60);
    }

    #[test]
    fn glob_zone() {
        assert!(glob_match("*.prod.example.com", "foo.prod.example.com"));
        assert!(!glob_match("*.prod.example.com", "prod.example.com.other"));
    }

    #[test]
    fn cidr_contains_ip() {
        assert_eq!(
            match_ip_or_cidr("10.0.0.0/16", "10.0.4.12"),
            Some(95)
        );
        assert!(match_ip_or_cidr("10.0.0.0/16", "11.0.0.1").is_none());
    }

    #[test]
    fn partial_ip_fragment() {
        assert!(match_ip_or_cidr("10.0.4", "10.0.4.0/24").is_some());
    }

    #[test]
    fn infer_mode_glob_and_ip() {
        assert_eq!(infer_mode("api-*"), MatchMode::Glob);
        assert_eq!(infer_mode("10.0.0.0/16"), MatchMode::IpOrCidr);
        assert_eq!(infer_mode("foo"), MatchMode::Partial);
    }
}
