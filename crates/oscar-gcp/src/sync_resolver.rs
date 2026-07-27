//! GCP Cloud DNS policies / response policies / forwarding+peering zones → DnsResolverInventory.

use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_identity::Profile;
use oscar_tools::inventory::{DnsPolicyEntry, DnsResolverInventory};
use oscar_tools::sync::{gcloud_project_args, run_json_command, which_ok};

pub struct GcpDnsResolverSource;

#[async_trait]
pub trait DnsResolverInventorySource: Send + Sync {
    async fn sync_resolver(
        &self,
        profile: &Profile,
        region: Option<&str>,
    ) -> OscarResult<DnsResolverInventory>;
}

#[async_trait]
impl DnsResolverInventorySource for GcpDnsResolverSource {
    async fn sync_resolver(
        &self,
        profile: &Profile,
        _region: Option<&str>,
    ) -> OscarResult<DnsResolverInventory> {
        if !which_ok("gcloud").await {
            return Err(OscarError::Tool(
                "gcloud CLI not found on PATH — install Google Cloud SDK".into(),
            ));
        }
        if profile.account_ref.is_empty() || profile.account_ref == "unknown" {
            return Err(OscarError::Tool(
                "GCP profile needs account_ref set to the GCP project id".into(),
            ));
        }

        let proj = gcloud_project_args(profile);

        // C5: DNS policies
        let mut pol_args = vec![
            "dns".into(),
            "policies".into(),
            "list".into(),
            "--format=json".into(),
        ];
        pol_args.extend(proj.clone());
        let pa: Vec<&str> = pol_args.iter().map(|s| s.as_str()).collect();
        let policies = run_json_command("gcloud", &pa).await.ok();

        // C6: response policies
        let mut rp_args = vec![
            "dns".into(),
            "response-policies".into(),
            "list".into(),
            "--format=json".into(),
        ];
        rp_args.extend(proj.clone());
        let ra: Vec<&str> = rp_args.iter().map(|s| s.as_str()).collect();
        let response_policies = run_json_command("gcloud", &ra).await.ok();

        // C5: managed zones — mark forwarding / peering
        let mut z_args = vec![
            "dns".into(),
            "managed-zones".into(),
            "list".into(),
            "--format=json".into(),
        ];
        z_args.extend(proj);
        let za: Vec<&str> = z_args.iter().map(|s| s.as_str()).collect();
        let zones = run_json_command("gcloud", &za).await.ok();

        Ok(map_gcp_to_dns_resolver_inventory(
            &profile.id,
            policies.as_ref(),
            response_policies.as_ref(),
            zones.as_ref(),
        ))
    }
}

pub fn map_gcp_to_dns_resolver_inventory(
    profile_id: &str,
    policies: Option<&serde_json::Value>,
    response_policies: Option<&serde_json::Value>,
    zones: Option<&serde_json::Value>,
) -> DnsResolverInventory {
    let mut policy_entries = Vec::new();

    if let Some(arr) = policies.and_then(|v| v.as_array()) {
        for p in arr {
            let name = p
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            let mut networks = Vec::new();
            if let Some(nets) = p.get("networks").and_then(|v| v.as_array()) {
                for n in nets {
                    if let Some(url) = n
                        .get("networkUrl")
                        .or_else(|| n.get("network"))
                        .and_then(|v| v.as_str())
                    {
                        networks.push(url.to_string());
                    } else if let Some(s) = n.as_str() {
                        networks.push(s.to_string());
                    }
                }
            }
            let mut alts = Vec::new();
            if let Some(servers) = p
                .get("alternativeNameServerConfig")
                .and_then(|v| v.get("targetNameServers"))
                .and_then(|v| v.as_array())
            {
                for s in servers {
                    if let Some(ip) = s.get("ipv4Address").and_then(|v| v.as_str()) {
                        alts.push(ip.to_string());
                    }
                }
            }
            policy_entries.push(DnsPolicyEntry {
                id: name.clone(),
                name: Some(name),
                policy_type: Some("policy".into()),
                description: p
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.into()),
                networks,
                alternative_name_servers: alts,
                enable_inbound_forwarding: p
                    .get("enableInboundForwarding")
                    .and_then(|v| v.as_bool()),
                enable_logging: p.get("enableLogging").and_then(|v| v.as_bool()),
                domains: vec![],
            });
        }
    }

    if let Some(arr) = response_policies.and_then(|v| v.as_array()) {
        for p in arr {
            let name = p
                .get("responsePolicyName")
                .or_else(|| p.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            let mut networks = Vec::new();
            if let Some(nets) = p.get("networks").and_then(|v| v.as_array()) {
                for n in nets {
                    if let Some(url) = n
                        .get("networkUrl")
                        .or_else(|| n.get("network"))
                        .and_then(|v| v.as_str())
                    {
                        networks.push(url.to_string());
                    }
                }
            }
            policy_entries.push(DnsPolicyEntry {
                id: name.clone(),
                name: Some(name),
                policy_type: Some("response_policy".into()),
                description: p
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.into()),
                networks,
                alternative_name_servers: vec![],
                enable_inbound_forwarding: None,
                enable_logging: None,
                domains: vec![],
            });
        }
    }

    // Forwarding / peering zones as policy-like rows for forwarding map
    if let Some(arr) = zones.and_then(|v| v.as_array()) {
        for z in arr {
            let ztype = z
                .get("visibility")
                .and_then(|v| v.as_str())
                .unwrap_or("public");
            let name = z
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let dns_name = z
                .get("dnsName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // forwardingConfig present → forwarding zone
            if z.get("forwardingConfig").is_some() {
                let mut alts = Vec::new();
                if let Some(targets) = z
                    .pointer("/forwardingConfig/targetNameServers")
                    .and_then(|v| v.as_array())
                {
                    for t in targets {
                        if let Some(ip) = t.get("ipv4Address").and_then(|v| v.as_str()) {
                            alts.push(ip.to_string());
                        }
                    }
                }
                policy_entries.push(DnsPolicyEntry {
                    id: name.clone(),
                    name: Some(name),
                    policy_type: Some("forwarding_zone".into()),
                    description: Some(format!("dnsName={dns_name}")),
                    networks: vec![],
                    alternative_name_servers: alts,
                    enable_inbound_forwarding: None,
                    enable_logging: None,
                    domains: if dns_name.is_empty() {
                        vec![]
                    } else {
                        vec![dns_name]
                    },
                });
            } else if z.get("peeringConfig").is_some() {
                let mut nets = Vec::new();
                if let Some(url) = z
                    .pointer("/peeringConfig/targetNetwork/networkUrl")
                    .and_then(|v| v.as_str())
                {
                    nets.push(url.to_string());
                }
                policy_entries.push(DnsPolicyEntry {
                    id: name.clone(),
                    name: Some(name),
                    policy_type: Some("peering_zone".into()),
                    description: Some(format!("visibility={ztype} dnsName={dns_name}")),
                    networks: nets,
                    alternative_name_servers: vec![],
                    enable_inbound_forwarding: None,
                    enable_logging: None,
                    domains: if dns_name.is_empty() {
                        vec![]
                    } else {
                        vec![dns_name]
                    },
                });
            }
        }
    }

    DnsResolverInventory {
        profile_id: profile_id.into(),
        cloud: Cloud::Gcp,
        region: None,
        endpoints: vec![],
        rules: vec![],
        firewall_rule_groups: vec![],
        query_log_configs: vec![],
        profiles: vec![],
        policies: policy_entries,
        vnet_links: vec![],
        private_resolvers: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::{MatchMode, PatternQuery, ResourceKind};
    use oscar_tools::scan_dns_resolver_inventory;
    use serde_json::json;

    #[test]
    fn maps_policy_and_forwarding_zone() {
        let policies = json!([{
            "name": "inbound-onprem",
            "description": "forward onprem",
            "enableInboundForwarding": true,
            "networks": [{"networkUrl": "projects/p/global/networks/default"}],
            "alternativeNameServerConfig": {
                "targetNameServers": [{"ipv4Address": "10.0.0.53"}]
            }
        }]);
        let zones = json!([{
            "name": "fwd-corp",
            "dnsName": "corp.internal.",
            "visibility": "private",
            "forwardingConfig": {
                "targetNameServers": [{"ipv4Address": "192.168.1.10"}]
            }
        }]);
        let inv = map_gcp_to_dns_resolver_inventory(
            "gcp-p",
            Some(&policies),
            None,
            Some(&zones),
        );
        assert!(inv
            .policies
            .iter()
            .any(|p| p.policy_type.as_deref() == Some("policy")));
        assert!(inv
            .policies
            .iter()
            .any(|p| p.policy_type.as_deref() == Some("forwarding_zone")));
        let q = PatternQuery {
            pattern: "corp.internal".into(),
            mode: MatchMode::Partial,
            profile_id: None,
            region: None,
            limit: 20,
        };
        let r = scan_dns_resolver_inventory(&inv, &q);
        assert!(r.hits.iter().any(|h| h.kind == ResourceKind::DnsPolicy));
    }
}
