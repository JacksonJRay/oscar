//! AWS Route 53 Resolver + DNS Firewall + query logging → unified [`DnsResolverInventory`].

use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_identity::{
    auth_request_from_error, resolve_aws_process_creds, BinaryInventory, Profile,
};
use oscar_tools::inventory::{
    DnsProfileEntry, DnsResolverInventory, FirewallRuleGroupEntry, QueryLogConfigEntry,
    ResolverEndpointEntry, ResolverRuleEntry,
};
use oscar_tools::sync::{run_json_command_with_env, which_ok};

/// Live fetch of regional Route 53 Resolver inventory.
pub struct AwsDnsResolverSource;

#[async_trait]
pub trait DnsResolverInventorySource: Send + Sync {
    async fn sync_resolver(
        &self,
        profile: &Profile,
        region: Option<&str>,
    ) -> OscarResult<DnsResolverInventory>;
}

#[async_trait]
impl DnsResolverInventorySource for AwsDnsResolverSource {
    async fn sync_resolver(
        &self,
        profile: &Profile,
        region: Option<&str>,
    ) -> OscarResult<DnsResolverInventory> {
        if !which_ok("aws").await {
            return Err(OscarError::Tool(
                "AWS CLI (`aws`) not found on PATH — install AWS CLI v2 so oscar can invoke it"
                    .into(),
            ));
        }

        let binaries = BinaryInventory::detect();
        let creds = resolve_aws_process_creds(profile, &binaries).map_err(|a| {
            OscarError::AuthRequired(format!(
                "{} | hints: {}",
                a.reason,
                a.hint_commands.join(" ; ")
            ))
        })?;
        let env: Vec<(String, String)> = creds.env.into_iter().collect();

        let region = region
            .map(|s| s.to_string())
            .or_else(|| profile.default_region.clone())
            .unwrap_or_else(|| "us-east-1".into());

        let endpoints_json = r53r_json(&env, &region, "list-resolver-endpoints")
            .await
            .map_err(|e| map_err(profile, e))?;
        let rules_json = r53r_json(&env, &region, "list-resolver-rules")
            .await
            .map_err(|e| map_err(profile, e))?;
        // Best-effort extras (permissions may differ)
        let firewall_json = r53r_json(&env, &region, "list-firewall-rule-groups")
            .await
            .ok();
        let query_log_json = r53r_json(&env, &region, "list-resolver-query-log-configs")
            .await
            .ok();
        // C2: Route 53 Profiles (global-ish API; region still required by CLI)
        let profiles_json = run_json_command_with_env(
            "aws",
            &[
                "route53profiles",
                "list-profiles",
                "--region",
                &region,
                "--output",
                "json",
            ],
            &env,
        )
        .await
        .ok();

        Ok(map_aws_to_dns_resolver_inventory(
            &profile.id,
            Some(region.as_str()),
            &endpoints_json,
            &rules_json,
            firewall_json.as_ref(),
            query_log_json.as_ref(),
            profiles_json.as_ref(),
        ))
    }
}

async fn r53r_json(
    env: &[(String, String)],
    region: &str,
    op: &str,
) -> OscarResult<serde_json::Value> {
    let args = [
        "route53resolver",
        op,
        "--region",
        region,
        "--output",
        "json",
    ];
    run_json_command_with_env("aws", &args, env).await
}

fn map_err(profile: &Profile, e: OscarError) -> OscarError {
    let text = e.to_string();
    if let Some(a) = auth_request_from_error(Cloud::Aws, Some(&profile.id), &text) {
        return OscarError::AuthRequired(format!(
            "{} | {}",
            a.reason,
            a.hint_commands.join(" ; ")
        ));
    }
    e
}

/// Pure mapper (unit-testable).
pub fn map_aws_to_dns_resolver_inventory(
    profile_id: &str,
    region: Option<&str>,
    endpoints: &serde_json::Value,
    rules: &serde_json::Value,
    firewall: Option<&serde_json::Value>,
    query_logs: Option<&serde_json::Value>,
    profiles: Option<&serde_json::Value>,
) -> DnsResolverInventory {
    let mut endpoint_entries = Vec::new();
    if let Some(arr) = endpoints
        .get("ResolverEndpoints")
        .and_then(|v| v.as_array())
    {
        for e in arr {
            let id = e
                .get("Id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            let mut subnet_ids = Vec::new();
            let mut ip_addresses = Vec::new();
            if let Some(ips) = e.get("IpAddresses").and_then(|v| v.as_array()) {
                for ip in ips {
                    if let Some(s) = ip.get("SubnetId").and_then(|v| v.as_str()) {
                        subnet_ids.push(s.to_string());
                    }
                    if let Some(a) = ip
                        .get("Ip")
                        .or_else(|| ip.get("Ipv6"))
                        .and_then(|v| v.as_str())
                    {
                        ip_addresses.push(a.to_string());
                    }
                }
            }
            // list-resolver-endpoints may not include IpAddresses; keep subnets empty
            let mut sgs = Vec::new();
            if let Some(arr) = e.get("SecurityGroupIds").and_then(|v| v.as_array()) {
                for s in arr {
                    if let Some(id) = s.as_str() {
                        sgs.push(id.to_string());
                    }
                }
            }
            endpoint_entries.push(ResolverEndpointEntry {
                id,
                name: e.get("Name").and_then(|v| v.as_str()).map(|s| s.into()),
                direction: e
                    .get("Direction")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                status: e.get("Status").and_then(|v| v.as_str()).map(|s| s.into()),
                vpc_id: e
                    .get("HostVPCId")
                    .and_then(|v| v.as_str())
                    .map(|s| s.into()),
                subnet_ids,
                ip_addresses,
                security_group_ids: sgs,
            });
        }
    }

    let mut rule_entries = Vec::new();
    if let Some(arr) = rules.get("ResolverRules").and_then(|v| v.as_array()) {
        for r in arr {
            let id = r
                .get("Id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            let mut target_ips = Vec::new();
            if let Some(tips) = r.get("TargetIps").and_then(|v| v.as_array()) {
                for t in tips {
                    if let Some(ip) = t.get("Ip").and_then(|v| v.as_str()) {
                        let port = t.get("Port").and_then(|v| v.as_u64());
                        if let Some(p) = port {
                            target_ips.push(format!("{ip}:{p}"));
                        } else {
                            target_ips.push(ip.to_string());
                        }
                    }
                }
            }
            rule_entries.push(ResolverRuleEntry {
                id,
                name: r.get("Name").and_then(|v| v.as_str()).map(|s| s.into()),
                rule_type: r
                    .get("RuleType")
                    .and_then(|v| v.as_str())
                    .map(|s| s.into()),
                domain_name: r
                    .get("DomainName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                status: r.get("Status").and_then(|v| v.as_str()).map(|s| s.into()),
                resolver_endpoint_id: r
                    .get("ResolverEndpointId")
                    .and_then(|v| v.as_str())
                    .map(|s| s.into()),
                target_ips,
                vpc_ids: vec![], // associations need list-resolver-rule-associations
            });
        }
    }

    let mut firewall_entries = Vec::new();
    if let Some(arr) = firewall
        .and_then(|v| v.get("FirewallRuleGroups"))
        .and_then(|v| v.as_array())
    {
        for f in arr {
            let id = f
                .get("Id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            firewall_entries.push(FirewallRuleGroupEntry {
                id,
                name: f.get("Name").and_then(|v| v.as_str()).map(|s| s.into()),
                status: f
                    .get("Status")
                    .or_else(|| f.get("MutationProtection"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.into()),
                owner_id: f.get("OwnerId").and_then(|v| v.as_str()).map(|s| s.into()),
                rule_count: f
                    .get("RuleCount")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32),
                share_status: f
                    .get("ShareStatus")
                    .and_then(|v| v.as_str())
                    .map(|s| s.into()),
            });
        }
    }

    let mut query_log_entries = Vec::new();
    if let Some(arr) = query_logs
        .and_then(|v| v.get("ResolverQueryLogConfigs"))
        .and_then(|v| v.as_array())
    {
        for q in arr {
            let id = q
                .get("Id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            query_log_entries.push(QueryLogConfigEntry {
                id,
                name: q.get("Name").and_then(|v| v.as_str()).map(|s| s.into()),
                destination_arn: q
                    .get("DestinationArn")
                    .and_then(|v| v.as_str())
                    .map(|s| s.into()),
                status: q.get("Status").and_then(|v| v.as_str()).map(|s| s.into()),
                association_count: q
                    .get("AssociationCount")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32),
                owner_id: q.get("OwnerId").and_then(|v| v.as_str()).map(|s| s.into()),
            });
        }
    }

    let mut profile_entries = Vec::new();
    if let Some(arr) = profiles
        .and_then(|v| v.get("ProfileSummaries").or_else(|| v.get("Profiles")))
        .and_then(|v| v.as_array())
    {
        for p in arr {
            let id = p
                .get("Id")
                .or_else(|| p.get("Arn"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            profile_entries.push(DnsProfileEntry {
                id,
                name: p.get("Name").and_then(|v| v.as_str()).map(|s| s.into()),
                status: p.get("Status").and_then(|v| v.as_str()).map(|s| s.into()),
                owner_id: p.get("OwnerId").and_then(|v| v.as_str()).map(|s| s.into()),
                share_status: p
                    .get("ShareStatus")
                    .and_then(|v| v.as_str())
                    .map(|s| s.into()),
                associations: vec![],
            });
        }
    }

    DnsResolverInventory {
        profile_id: profile_id.into(),
        cloud: Cloud::Aws,
        region: region.map(|s| s.to_string()),
        endpoints: endpoint_entries,
        rules: rule_entries,
        firewall_rule_groups: firewall_entries,
        query_log_configs: query_log_entries,
        profiles: profile_entries,
        policies: vec![],
        vnet_links: vec![],
        private_resolvers: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::ResourceKind;
    use oscar_tools::scan_dns_resolver_inventory;
    use oscar_core::{MatchMode, PatternQuery};
    use serde_json::json;

    #[test]
    fn maps_endpoints_rules_firewall_query_logs() {
        let endpoints = json!({
            "ResolverEndpoints": [{
                "Id": "rslvr-in-abc",
                "Name": "inbound-corp",
                "Direction": "INBOUND",
                "Status": "OPERATIONAL",
                "HostVPCId": "vpc-123",
                "SecurityGroupIds": ["sg-1"]
            }]
        });
        let rules = json!({
            "ResolverRules": [{
                "Id": "rslvr-rr-xyz",
                "Name": "onprem-corp",
                "RuleType": "FORWARD",
                "DomainName": "corp.internal.",
                "Status": "COMPLETE",
                "ResolverEndpointId": "rslvr-out-1",
                "TargetIps": [{"Ip": "10.0.0.53", "Port": 53}]
            }]
        });
        let firewall = json!({
            "FirewallRuleGroups": [{
                "Id": "rslvr-frg-1",
                "Name": "block-malware",
                "OwnerId": "111122223333",
                "RuleCount": 12,
                "ShareStatus": "NOT_SHARED"
            }]
        });
        let qlogs = json!({
            "ResolverQueryLogConfigs": [{
                "Id": "rqlc-1",
                "Name": "vpc-queries",
                "DestinationArn": "arn:aws:logs:us-east-1:111:log-group:/r53",
                "Status": "CREATED",
                "AssociationCount": 2
            }]
        });
        let inv = map_aws_to_dns_resolver_inventory(
            "aws-p",
            Some("us-east-1"),
            &endpoints,
            &rules,
            Some(&firewall),
            Some(&qlogs),
            None,
        );
        assert_eq!(inv.endpoints.len(), 1);
        assert_eq!(inv.endpoints[0].direction, "INBOUND");
        assert_eq!(inv.rules.len(), 1);
        assert_eq!(inv.rules[0].domain_name, "corp.internal.");
        assert_eq!(inv.rules[0].target_ips, vec!["10.0.0.53:53"]);
        assert_eq!(inv.firewall_rule_groups.len(), 1);
        assert_eq!(inv.query_log_configs.len(), 1);

        let q = PatternQuery {
            pattern: "corp.internal".into(),
            mode: MatchMode::Partial,
            profile_id: None,
            region: None,
            limit: 20,
        };
        let r = scan_dns_resolver_inventory(&inv, &q);
        assert!(r
            .hits
            .iter()
            .any(|h| h.kind == ResourceKind::DnsResolverRule));
    }
}
