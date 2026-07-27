//! Live kubectl → unified [`K8sInventory`] (+ optional NetworkInventory of pod/svc IPs).

use async_trait::async_trait;
use oscar_core::{Cloud, OscarError, OscarResult};
use oscar_tools::inventory::{AddressEntry, K8sInventory, K8sResourceEntry, NetworkInventory};
use oscar_tools::sync::{
    run_json_command, which_ok, write_k8s_cache, write_network_cache, K8sInventorySource,
};
use std::path::Path;

pub struct KubectlK8sSource {
    pub context: Option<String>,
}

#[async_trait]
impl K8sInventorySource for KubectlK8sSource {
    async fn sync_k8s(&self, context: Option<&str>) -> OscarResult<K8sInventory> {
        if !which_ok("kubectl").await {
            return Err(OscarError::Tool(
                "kubectl not found on PATH — install kubectl to sync cluster inventory".into(),
            ));
        }
        let ctx = context
            .map(|s| s.to_string())
            .or_else(|| self.context.clone());

        let mut pods_args = vec!["get".into(), "pods".into(), "-A".into(), "-o".into(), "json".into()];
        let mut svc_args = vec![
            "get".into(),
            "svc".into(),
            "-A".into(),
            "-o".into(),
            "json".into(),
        ];
        let mut node_args = vec!["get".into(), "nodes".into(), "-o".into(), "json".into()];
        let mut ns_args = vec!["get".into(), "ns".into(), "-o".into(), "json".into()];
        if let Some(ref c) = ctx {
            for a in [
                &mut pods_args,
                &mut svc_args,
                &mut node_args,
                &mut ns_args,
            ] {
                a.insert(0, "--context".into());
                a.insert(1, c.clone());
            }
        }

        let pods = run_json_args(&pods_args).await?;
        let svcs = run_json_args(&svc_args).await.ok();
        let nodes = run_json_args(&node_args).await.ok();
        let namespaces = run_json_args(&ns_args).await.ok();

        Ok(map_kubectl_to_k8s_inventory(
            ctx.as_deref(),
            None,
            &pods,
            svcs.as_ref(),
            nodes.as_ref(),
            namespaces.as_ref(),
        ))
    }
}

async fn run_json_args(args: &[String]) -> OscarResult<serde_json::Value> {
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_json_command("kubectl", &refs).await
}

pub fn map_kubectl_to_k8s_inventory(
    context: Option<&str>,
    profile_id: Option<&str>,
    pods: &serde_json::Value,
    svcs: Option<&serde_json::Value>,
    nodes: Option<&serde_json::Value>,
    namespaces: Option<&serde_json::Value>,
) -> K8sInventory {
    let mut resources = Vec::new();

    if let Some(items) = pods.get("items").and_then(|v| v.as_array()) {
        for p in items {
            let name = p
                .pointer("/metadata/name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let ns = p
                .pointer("/metadata/namespace")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let mut labels = Vec::new();
            if let Some(obj) = p.pointer("/metadata/labels").and_then(|v| v.as_object()) {
                for (k, v) in obj {
                    if let Some(vs) = v.as_str() {
                        labels.push(format!("{k}={vs}"));
                    }
                }
            }
            let mut ips = Vec::new();
            if let Some(ip) = p.pointer("/status/podIP").and_then(|v| v.as_str()) {
                ips.push(ip.to_string());
            }
            if let Some(host) = p.pointer("/status/hostIP").and_then(|v| v.as_str()) {
                ips.push(host.to_string());
            }
            let mut extra = Vec::new();
            if let Some(phase) = p.pointer("/status/phase").and_then(|v| v.as_str()) {
                extra.push(format!("phase={phase}"));
            }
            if let Some(node) = p.pointer("/spec/nodeName").and_then(|v| v.as_str()) {
                extra.push(format!("node={node}"));
            }
            if name.is_empty() {
                continue;
            }
            resources.push(K8sResourceEntry {
                kind: "Pod".into(),
                name,
                namespace: ns,
                labels,
                ips,
                extra,
            });
        }
    }

    if let Some(items) = svcs.and_then(|v| v.get("items")).and_then(|v| v.as_array()) {
        for s in items {
            let name = s
                .pointer("/metadata/name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let ns = s
                .pointer("/metadata/namespace")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let mut ips = Vec::new();
            if let Some(cip) = s.pointer("/spec/clusterIP").and_then(|v| v.as_str()) {
                if cip != "None" {
                    ips.push(cip.to_string());
                }
            }
            if let Some(ing) = s.pointer("/status/loadBalancer/ingress").and_then(|v| v.as_array())
            {
                for i in ing {
                    if let Some(ip) = i.get("ip").and_then(|v| v.as_str()) {
                        ips.push(ip.to_string());
                    }
                    if let Some(h) = i.get("hostname").and_then(|v| v.as_str()) {
                        ips.push(h.to_string());
                    }
                }
            }
            let mut extra = Vec::new();
            if let Some(t) = s.pointer("/spec/type").and_then(|v| v.as_str()) {
                extra.push(format!("type={t}"));
            }
            if name.is_empty() {
                continue;
            }
            resources.push(K8sResourceEntry {
                kind: "Service".into(),
                name,
                namespace: ns,
                labels: vec![],
                ips,
                extra,
            });
        }
    }

    if let Some(items) = nodes.and_then(|v| v.get("items")).and_then(|v| v.as_array()) {
        for n in items {
            let name = n
                .pointer("/metadata/name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mut ips = Vec::new();
            if let Some(addrs) = n.pointer("/status/addresses").and_then(|v| v.as_array()) {
                for a in addrs {
                    if let Some(addr) = a.get("address").and_then(|v| v.as_str()) {
                        ips.push(addr.to_string());
                    }
                }
            }
            if name.is_empty() {
                continue;
            }
            resources.push(K8sResourceEntry {
                kind: "Node".into(),
                name,
                namespace: None,
                labels: vec![],
                ips,
                extra: vec![],
            });
        }
    }

    if let Some(items) = namespaces
        .and_then(|v| v.get("items"))
        .and_then(|v| v.as_array())
    {
        for n in items {
            let name = n
                .pointer("/metadata/name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            resources.push(K8sResourceEntry {
                kind: "Namespace".into(),
                name,
                namespace: None,
                labels: vec![],
                ips: vec![],
                extra: vec![],
            });
        }
    }

    K8sInventory {
        context: context.map(|s| s.to_string()),
        profile_id: profile_id.map(|s| s.to_string()),
        resources,
    }
}

/// Map k8s resource IPs into unified NetworkInventory addresses (F9) for pattern locate.
pub fn k8s_inventory_to_network(inv: &K8sInventory) -> NetworkInventory {
    let profile = inv
        .profile_id
        .clone()
        .or_else(|| inv.context.clone().map(|c| format!("k8s-{c}")))
        .unwrap_or_else(|| "k8s-default".into());
    let mut addresses = Vec::new();
    for r in &inv.resources {
        for (i, ip) in r.ips.iter().enumerate() {
            if ip.is_empty() || ip == "None" {
                continue;
            }
            let kind_lc = r.kind.to_ascii_lowercase();
            let kind = match kind_lc.as_str() {
                "pod" => {
                    if i == 0 {
                        "pod_ip".to_string()
                    } else {
                        "host_ip".to_string()
                    }
                }
                "service" => "service_ip".to_string(),
                "node" => "node_ip".to_string(),
                other => other.to_string(),
            };
            let name = match &r.namespace {
                Some(ns) => format!("{}/{}", ns, r.name),
                None => r.name.clone(),
            };
            addresses.push(AddressEntry {
                id: Some(format!("{}:{}:{}", r.kind, name, ip)),
                name: Some(name),
                ip: ip.clone(),
                kind: Some(kind),
                vpc_id: None,
                subnet_id: None,
                region: inv.context.clone(),
            });
        }
    }
    NetworkInventory {
        profile_id: profile,
        cloud: Cloud::K8s,
        region: Some("cluster".into()),
        vpcs: vec![],
        subnets: vec![],
        addresses,
    }
}

/// Sync and write cache under config_dir/cache/k8s/<key>.json
/// Also writes NetworkInventory of pod/svc/node IPs for network.ip.locate (F9).
pub async fn sync_and_cache(
    config_dir: &Path,
    context: Option<&str>,
    profile_id: Option<&str>,
) -> OscarResult<K8sInventory> {
    let source = KubectlK8sSource {
        context: context.map(|s| s.to_string()),
    };
    let mut inv = source.sync_k8s(context).await?;
    inv.profile_id = profile_id.map(|s| s.to_string());
    let key = context
        .or(profile_id)
        .unwrap_or("default")
        .replace(['/', '\\', ' '], "-");
    write_k8s_cache(config_dir, &key, &inv)?;
    // F9: join cluster IPs into NetworkInventory for multi-cloud IP pattern locate
    let net = k8s_inventory_to_network(&inv);
    let _ = write_network_cache(config_dir, &net);
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_pod_and_service() {
        let pods = json!({
            "items": [{
                "metadata": { "name": "nginx", "namespace": "default", "labels": { "app": "web" } },
                "status": { "podIP": "10.0.1.5", "hostIP": "192.168.1.10", "phase": "Running" },
                "spec": { "nodeName": "node-a" }
            }]
        });
        let svcs = json!({
            "items": [{
                "metadata": { "name": "nginx", "namespace": "default" },
                "spec": { "clusterIP": "10.96.0.10", "type": "ClusterIP" }
            }]
        });
        let inv = map_kubectl_to_k8s_inventory(Some("ctx"), None, &pods, Some(&svcs), None, None);
        assert!(inv.resources.iter().any(|r| r.kind == "Pod" && r.ips.contains(&"10.0.1.5".into())));
        assert!(inv.resources.iter().any(|r| r.kind == "Service"));
        let net = k8s_inventory_to_network(&inv);
        assert!(net.addresses.iter().any(|a| a.ip == "10.0.1.5"));
        assert!(net.addresses.iter().any(|a| a.kind.as_deref() == Some("service_ip")));
    }
}
