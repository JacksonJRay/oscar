//! Azure Private DNS VNet links + DNS Private Resolver → DnsResolverInventory.

use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_identity::{auth_request_from_error, resolve_azure_hints, BinaryInventory, Profile};
use oscar_tools::inventory::{
    DnsPrivateResolverEntry, DnsResolverInventory, DnsVnetLinkEntry,
};
use oscar_tools::sync::{run_json_command, which_ok};

pub struct AzureDnsResolverSource;

#[async_trait]
pub trait DnsResolverInventorySource: Send + Sync {
    async fn sync_resolver(
        &self,
        profile: &Profile,
        region: Option<&str>,
    ) -> OscarResult<DnsResolverInventory>;
}

#[async_trait]
impl DnsResolverInventorySource for AzureDnsResolverSource {
    async fn sync_resolver(
        &self,
        profile: &Profile,
        region: Option<&str>,
    ) -> OscarResult<DnsResolverInventory> {
        if !which_ok("az").await {
            return Err(OscarError::Tool(
                "Azure CLI (`az`) not found on PATH — install Azure CLI".into(),
            ));
        }
        let binaries = BinaryInventory::detect();
        resolve_azure_hints(profile, &binaries).map_err(|a| {
            OscarError::AuthRequired(format!("{} | {}", a.reason, a.hint_commands.join(" ; ")))
        })?;

        // Private DNS zones
        let zones = run_json_command(
            "az",
            &["network", "private-dns", "zone", "list", "-o", "json"],
        )
        .await
        .map_err(|e| map_err(profile, e))?;

        let mut links = Vec::new();
        if let Some(arr) = zones.as_array() {
            for z in arr {
                let zname = z.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let rg = z
                    .get("resourceGroup")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if zname.is_empty() || rg.is_empty() {
                    continue;
                }
                match run_json_command(
                    "az",
                    &[
                        "network",
                        "private-dns",
                        "link",
                        "vnet",
                        "list",
                        "-g",
                        rg,
                        "-z",
                        zname,
                        "-o",
                        "json",
                    ],
                )
                .await
                {
                    Ok(v) => {
                        if let Some(larr) = v.as_array() {
                            for l in larr {
                                links.push(map_vnet_link(zname, l));
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        // C8: DNS Private Resolvers
        let mut resolvers = Vec::new();
        if let Ok(v) = run_json_command(
            "az",
            &[
                "network",
                "private-dns",
                "resolver",
                "list",
                "-o",
                "json",
            ],
        )
        .await
        {
            if let Some(arr) = v.as_array() {
                for r in arr {
                    resolvers.push(map_private_resolver(r).await);
                }
            }
        }

        Ok(DnsResolverInventory {
            profile_id: profile.id.clone(),
            cloud: Cloud::Azure,
            region: region
                .map(|s| s.to_string())
                .or_else(|| profile.default_region.clone()),
            endpoints: vec![],
            rules: vec![],
            firewall_rule_groups: vec![],
            query_log_configs: vec![],
            profiles: vec![],
            policies: vec![],
            vnet_links: links,
            private_resolvers: resolvers,
        })
    }
}

fn map_err(profile: &Profile, e: OscarError) -> OscarError {
    let text = e.to_string();
    if let Some(a) = auth_request_from_error(Cloud::Azure, Some(&profile.id), &text) {
        return OscarError::AuthRequired(format!(
            "{} | {}",
            a.reason,
            a.hint_commands.join(" ; ")
        ));
    }
    e
}

pub fn map_vnet_link(zone_name: &str, l: &serde_json::Value) -> DnsVnetLinkEntry {
    DnsVnetLinkEntry {
        id: l
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name: l.get("name").and_then(|v| v.as_str()).map(|s| s.into()),
        zone_name: zone_name.into(),
        vnet_id: l
            .get("virtualNetwork")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .or_else(|| l.pointer("/virtualNetwork/id").and_then(|v| v.as_str()))
            .map(|s| s.into()),
        registration_enabled: l
            .get("registrationEnabled")
            .and_then(|v| v.as_bool()),
        provisioning_state: l
            .get("provisioningState")
            .and_then(|v| v.as_str())
            .map(|s| s.into()),
        resolution_policy: l
            .get("resolutionPolicy")
            .and_then(|v| v.as_str())
            .map(|s| s.into()),
    }
}

pub async fn map_private_resolver(r: &serde_json::Value) -> DnsPrivateResolverEntry {
    let id = r
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let name = r.get("name").and_then(|v| v.as_str()).map(|s| s.into());
    let rg = r
        .get("resourceGroup")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let rname = r.get("name").and_then(|v| v.as_str()).unwrap_or("");

    let mut endpoints = Vec::new();
    let mut rulesets = Vec::new();

    if !rg.is_empty() && !rname.is_empty() {
        if let Ok(v) = run_json_command(
            "az",
            &[
                "network",
                "private-dns",
                "resolver",
                "inbound-endpoint",
                "list",
                "-g",
                rg,
                "--dns-resolver-name",
                rname,
                "-o",
                "json",
            ],
        )
        .await
        {
            if let Some(arr) = v.as_array() {
                for e in arr {
                    let en = e.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                    let ip = e
                        .pointer("/ipConfigurations/0/privateIpAddress")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    endpoints.push(format!("inbound:{en}:{ip}"));
                }
            }
        }
        if let Ok(v) = run_json_command(
            "az",
            &[
                "network",
                "private-dns",
                "resolver",
                "outbound-endpoint",
                "list",
                "-g",
                rg,
                "--dns-resolver-name",
                rname,
                "-o",
                "json",
            ],
        )
        .await
        {
            if let Some(arr) = v.as_array() {
                for e in arr {
                    let en = e.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                    endpoints.push(format!("outbound:{en}"));
                }
            }
        }
        if let Ok(v) = run_json_command(
            "az",
            &[
                "network",
                "private-dns",
                "resolver",
                "forwarding-ruleset",
                "list",
                "-g",
                rg,
                "-o",
                "json",
            ],
        )
        .await
        {
            if let Some(arr) = v.as_array() {
                for rs in arr {
                    if let Some(n) = rs.get("name").and_then(|x| x.as_str()) {
                        rulesets.push(n.to_string());
                    }
                }
            }
        }
    }

    DnsPrivateResolverEntry {
        id,
        name,
        status: r
            .get("provisioningState")
            .and_then(|v| v.as_str())
            .map(|s| s.into()),
        vnet_id: r
            .pointer("/virtualNetwork/id")
            .and_then(|v| v.as_str())
            .map(|s| s.into()),
        location: r
            .get("location")
            .and_then(|v| v.as_str())
            .map(|s| s.into()),
        endpoints,
        rulesets,
    }
}

/// Pure mapper for unit tests (no CLI).
#[cfg(test)]
pub fn map_azure_links_and_resolvers(
    profile_id: &str,
    links: Vec<DnsVnetLinkEntry>,
    resolvers: Vec<DnsPrivateResolverEntry>,
) -> DnsResolverInventory {
    DnsResolverInventory {
        profile_id: profile_id.into(),
        cloud: Cloud::Azure,
        region: None,
        endpoints: vec![],
        rules: vec![],
        firewall_rule_groups: vec![],
        query_log_configs: vec![],
        profiles: vec![],
        policies: vec![],
        vnet_links: links,
        private_resolvers: resolvers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::{MatchMode, PatternQuery, ResourceKind};
    use oscar_tools::scan_dns_resolver_inventory;
    use serde_json::json;

    #[test]
    fn maps_vnet_link() {
        let l = json!({
            "id": "/subscriptions/s/rg/providers/Microsoft.Network/privateDnsZones/corp.internal/virtualNetworkLinks/link1",
            "name": "link1",
            "registrationEnabled": true,
            "provisioningState": "Succeeded",
            "virtualNetwork": { "id": "/subscriptions/s/.../virtualNetworks/vnet1" }
        });
        let link = map_vnet_link("corp.internal", &l);
        assert_eq!(link.zone_name, "corp.internal");
        assert_eq!(link.name.as_deref(), Some("link1"));
        let inv = map_azure_links_and_resolvers("az-p", vec![link], vec![]);
        let q = PatternQuery {
            pattern: "corp.internal".into(),
            mode: MatchMode::Partial,
            profile_id: None,
            region: None,
            limit: 10,
        };
        let r = scan_dns_resolver_inventory(&inv, &q);
        assert!(r.hits.iter().any(|h| h.kind == ResourceKind::DnsVnetLink));
    }
}
