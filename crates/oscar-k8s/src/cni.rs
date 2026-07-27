//! Track F — Kubernetes CNI troubleshooting (Cilium / Calico / generic).

use async_trait::async_trait;
use oscar_core::{Capability, Cloud, ToolDomain};
use oscar_tools::sync::{run_json_command, which_ok};
use oscar_tools::{Tool, ToolContext, ToolMeta, ToolResult};
use serde_json::json;
use std::process::Stdio;

pub fn register_cni(registry: &mut oscar_tools::ToolRegistry) {
    use std::sync::Arc;
    registry.register(Arc::new(K8sCniDetect));
    registry.register(Arc::new(K8sHubbleObserve));
    registry.register(Arc::new(K8sHubbleDiagnose));
    registry.register(Arc::new(K8sCiliumPolicyCheck));
    registry.register(Arc::new(K8sCalicoNodeStatus));
    registry.register(Arc::new(K8sCalicoPolicyPattern));
    registry.register(Arc::new(K8sCalicoBgpStatus));
    registry.register(Arc::new(K8sCniPodLogs));
    registry.register(Arc::new(K8sNetworkPolicyDenyNarrative));
    registry.register(Arc::new(K8sCoreDnsDiscover));
}

struct K8sCniDetect;
struct K8sHubbleObserve;
struct K8sHubbleDiagnose;
struct K8sCiliumPolicyCheck;
struct K8sCalicoNodeStatus;
struct K8sCalicoPolicyPattern;
struct K8sCalicoBgpStatus;
struct K8sCniPodLogs;
struct K8sNetworkPolicyDenyNarrative;
struct K8sCoreDnsDiscover;

fn ctx_args(context: Option<&str>) -> Vec<String> {
    let mut a = Vec::new();
    if let Some(c) = context {
        a.push("--context".into());
        a.push(c.into());
    }
    a
}

async fn kubectl_json(context: Option<&str>, args: &[&str]) -> Result<serde_json::Value, String> {
    if !which_ok("kubectl").await {
        return Err("kubectl not found on PATH".into());
    }
    let mut full: Vec<String> = ctx_args(context);
    full.extend(args.iter().map(|s| (*s).to_string()));
    let refs: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
    run_json_command("kubectl", &refs)
        .await
        .map_err(|e| e.to_string())
}

async fn run_text(program: &str, args: &[&str]) -> Result<String, String> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd
        .output()
        .await
        .map_err(|e| format!("failed to spawn `{program}`: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        return Err(format!(
            "{} failed: {} {}",
            program,
            stderr.trim(),
            stdout.trim()
        ));
    }
    Ok(stdout)
}

/// D5 — CoreDNS / cluster DNS + Service/EndpointSlice discovery.
#[async_trait]
impl Tool for K8sCoreDnsDiscover {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.coredns.discover".into(),
            name: "CoreDNS / cluster DNS discovery".into(),
            description: "Discover CoreDNS deployment/configmap, kube-dns Service, and optional EndpointSlices for cluster DNS path troubleshooting.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "k8s".into(),
                "coredns".into(),
                "dns".into(),
                "endpointslice".into(),
                "cluster".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "context": { "type": "string" },
                    "include_config": { "type": "boolean", "default": true }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let context = args.get("context").and_then(|v| v.as_str());
        let include_config = args
            .get("include_config")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let mut notes = Vec::new();
        let mut data = serde_json::Map::new();

        // CoreDNS pods
        match kubectl_json(
            context,
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "k8s-app=kube-dns",
                "-o",
                "json",
            ],
        )
        .await
        {
            Ok(v) => {
                let pods: Vec<_> = v
                    .get("items")
                    .and_then(|a| a.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|p| {
                                json!({
                                    "name": p.pointer("/metadata/name"),
                                    "phase": p.pointer("/status/phase"),
                                    "podIP": p.pointer("/status/podIP"),
                                    "node": p.pointer("/spec/nodeName"),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                data.insert("coredns_pods".into(), json!(pods));
            }
            Err(e) => notes.push(format!("coredns pods: {e}")),
        }

        // kube-dns Service
        match kubectl_json(
            context,
            &["get", "svc", "kube-dns", "-n", "kube-system", "-o", "json"],
        )
        .await
        {
            Ok(v) => {
                data.insert(
                    "kube_dns_service".into(),
                    json!({
                        "clusterIP": v.pointer("/spec/clusterIP"),
                        "ports": v.pointer("/spec/ports"),
                    }),
                );
            }
            Err(e) => notes.push(format!("kube-dns svc: {e}")),
        }

        // EndpointSlices
        match kubectl_json(
            context,
            &[
                "get",
                "endpointslices",
                "-n",
                "kube-system",
                "-l",
                "kubernetes.io/service-name=kube-dns",
                "-o",
                "json",
            ],
        )
        .await
        {
            Ok(v) => {
                data.insert("endpoint_slices".into(), v);
            }
            Err(e) => notes.push(format!("endpointslices: {e}")),
        }

        if include_config {
            match kubectl_json(
                context,
                &[
                    "get",
                    "configmap",
                    "coredns",
                    "-n",
                    "kube-system",
                    "-o",
                    "json",
                ],
            )
            .await
            {
                Ok(v) => {
                    let corefile = v
                        .pointer("/data/Corefile")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    // redact nothing heavy; Corefile rarely has secrets
                    data.insert(
                        "coredns_corefile".into(),
                        json!(if corefile.len() > 8000 {
                            format!("{}…", &corefile[..8000])
                        } else {
                            corefile.to_string()
                        }),
                    );
                }
                Err(e) => notes.push(format!("coredns configmap: {e}")),
            }
        }

        ToolResult::success(
            "CoreDNS / cluster DNS discovery complete",
            json!({
                "format": "CoreDnsDiscover",
                "context": context,
                "data": data,
                "notes": notes,
                "hints": [
                    "Pattern-search services: k8s.services.pattern.search",
                    "Private DNS hybrid: dns.forwarding.map after CSP resolver sync",
                ],
            }),
        )
    }
}

/// F1 — Detect CNI flavor from kube-system pods / DaemonSets.
#[async_trait]
impl Tool for K8sCniDetect {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.cni.detect".into(),
            name: "Detect cluster CNI flavor".into(),
            description: "Detect CNI (Cilium, Calico, AWS VPC CNI, Azure CNI, GKE Dataplane, Flannel, unknown) from kube-system pods/daemonsets. Use before Hubble/calicoctl tools.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s, Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "k8s".into(),
                "cni".into(),
                "cilium".into(),
                "calico".into(),
                "detect".into(),
                "hubble".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "context": { "type": "string" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let context = args.get("context").and_then(|v| v.as_str());
        let pods = match kubectl_json(
            context,
            &["get", "pods", "-n", "kube-system", "-o", "json"],
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                return ToolResult::from_error_text(Cloud::K8s, None, e);
            }
        };

        let mut evidence = Vec::new();
        let mut scores = std::collections::BTreeMap::<&str, u32>::new();
        if let Some(items) = pods.get("items").and_then(|v| v.as_array()) {
            for p in items {
                let name = p
                    .pointer("/metadata/name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let labels = p
                    .pointer("/metadata/labels")
                    .map(|v| v.to_string().to_ascii_lowercase())
                    .unwrap_or_default();
                let blob = format!("{name} {labels}");
                if blob.contains("cilium") {
                    *scores.entry("cilium").or_default() += 2;
                    evidence.push(format!("pod:{name}"));
                }
                if blob.contains("calico") || blob.contains("typha") {
                    *scores.entry("calico").or_default() += 2;
                    evidence.push(format!("pod:{name}"));
                }
                if blob.contains("aws-node") || blob.contains("amazon-k8s-cni") {
                    *scores.entry("aws-vpc-cni").or_default() += 2;
                    evidence.push(format!("pod:{name}"));
                }
                if blob.contains("azure-cni") || blob.contains("azure-npm") {
                    *scores.entry("azure-cni").or_default() += 2;
                    evidence.push(format!("pod:{name}"));
                }
                if blob.contains("gke-metadata") || blob.contains("netd") {
                    *scores.entry("gke").or_default() += 1;
                    evidence.push(format!("pod:{name}"));
                }
                if blob.contains("flannel") || blob.contains("cni-flannel") {
                    *scores.entry("flannel").or_default() += 2;
                    evidence.push(format!("pod:{name}"));
                }
                if blob.contains("kube-router") {
                    *scores.entry("kube-router").or_default() += 2;
                    evidence.push(format!("pod:{name}"));
                }
            }
        }

        let (flavor, score) = scores
            .into_iter()
            .max_by_key(|(_, s)| *s)
            .unwrap_or(("unknown", 0));

        let hints = match flavor {
            "cilium" => vec![
                "k8s.hubble.observe",
                "k8s.cilium.policy.check",
                "cilium status / hubble observe --verdict DROPPED",
            ],
            "calico" => vec![
                "k8s.calico.node.status",
                "k8s.calico.policy.pattern",
                "k8s.calico.bgp.status",
            ],
            "aws-vpc-cni" => vec!["k8s.cni.pod_logs (aws-node)", "aws.network.pattern.search"],
            _ => vec!["k8s.cni.pod_logs", "k8s.networkpolicy.deny.narrative"],
        };

        ToolResult::success(
            format!("CNI detected: {flavor} (score={score})"),
            json!({
                "format": "CniDetect",
                "flavor": flavor,
                "score": score,
                "evidence": evidence,
                "recommended_tools": hints,
                "context": context,
            }),
        )
    }
}

/// F2 — Wrap hubble observe patterns.
#[async_trait]
impl Tool for K8sHubbleObserve {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.hubble.observe".into(),
            name: "Hubble observe flows".into(),
            description: "Run hubble observe (or kubectl exec into cilium) for dropped/pod/namespace/L7 filters. Maps to a short path/blocker summary. Requires hubble CLI or cilium agent.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "k8s".into(),
                "cilium".into(),
                "hubble".into(),
                "cni".into(),
                "dropped".into(),
                "flows".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "context": { "type": "string" },
                    "verdict": { "type": "string", "description": "e.g. DROPPED, FORWARDED" },
                    "pod": { "type": "string" },
                    "namespace": { "type": "string" },
                    "to_pod": { "type": "string" },
                    "protocol": { "type": "string" },
                    "last": { "type": "integer", "default": 20, "description": "number of flows" },
                    "http": { "type": "boolean", "description": "enable L7 HTTP filter if supported" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let context = args.get("context").and_then(|v| v.as_str());
        let last = args
            .get("last")
            .and_then(|v| v.as_u64())
            .unwrap_or(20)
            .clamp(1, 200);
        let mut hubble_args: Vec<String> = vec![
            "observe".into(),
            "-n".into(),
            last.to_string(),
            "-o".into(),
            "json".into(),
        ];
        if let Some(v) = args.get("verdict").and_then(|x| x.as_str()) {
            hubble_args.push("--verdict".into());
            hubble_args.push(v.into());
        }
        if let Some(p) = args.get("pod").and_then(|x| x.as_str()) {
            hubble_args.push("--pod".into());
            hubble_args.push(p.into());
        }
        if let Some(ns) = args.get("namespace").and_then(|x| x.as_str()) {
            hubble_args.push("--namespace".into());
            hubble_args.push(ns.into());
        }
        if let Some(tp) = args.get("to_pod").and_then(|x| x.as_str()) {
            hubble_args.push("--to-pod".into());
            hubble_args.push(tp.into());
        }
        if let Some(proto) = args.get("protocol").and_then(|x| x.as_str()) {
            hubble_args.push("--protocol".into());
            hubble_args.push(proto.into());
        }
        if args.get("http").and_then(|v| v.as_bool()).unwrap_or(false) {
            hubble_args.push("--http-status".into());
            hubble_args.push("0-599".into());
        }

        // Prefer local hubble CLI
        if which_ok("hubble").await {
            let refs: Vec<&str> = hubble_args.iter().map(|s| s.as_str()).collect();
            match run_text("hubble", &refs).await {
                Ok(out) => {
                    return summarize_hubble_output(&out, context);
                }
                Err(e) => {
                    // fall through to kubectl exec
                    let _ = e;
                }
            }
        }

        // Fallback: kubectl -n kube-system exec ds/cilium -- hubble observe ...
        let mut kargs: Vec<String> = ctx_args(context);
        kargs.extend([
            "exec".into(),
            "-n".into(),
            "kube-system".into(),
            "ds/cilium".into(),
            "--".into(),
            "hubble".into(),
        ]);
        kargs.extend(hubble_args);
        let refs: Vec<&str> = kargs.iter().map(|s| s.as_str()).collect();
        match run_text("kubectl", &refs).await {
            Ok(out) => summarize_hubble_output(&out, context),
            Err(e) => ToolResult::error(format!(
                "hubble observe failed ({e}). Install hubble CLI or ensure cilium DaemonSet exists. Tips: cilium hubble port-forward; kubectl -n kube-system exec ds/cilium -- hubble observe --verdict DROPPED"
            )),
        }
    }
}

fn summarize_hubble_output(out: &str, context: Option<&str>) -> ToolResult {
    let mut flows = Vec::new();
    let mut dropped = 0usize;
    for line in out.lines().take(50) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
            let verdict = v
                .pointer("/verdict")
                .or_else(|| v.pointer("/flow/verdict"))
                .map(|x| x.to_string())
                .unwrap_or_default();
            if verdict.to_ascii_uppercase().contains("DROP") {
                dropped += 1;
            }
            flows.push(v);
        } else {
            flows.push(json!({ "raw": t }));
            if t.to_ascii_uppercase().contains("DROP") {
                dropped += 1;
            }
        }
    }
    ToolResult::success(
        format!(
            "Hubble: {} flow line(s), ~{dropped} drop-related",
            flows.len()
        ),
        json!({
            "format": "HubbleObserve",
            "context": context,
            "dropped_hint_count": dropped,
            "flows": flows,
            "blocker_summary": if dropped > 0 {
                "One or more DROPPED verdicts seen — check Cilium network policy / identity mismatch (k8s.cilium.policy.check, k8s.networkpolicy.deny.narrative)"
            } else {
                "No DROP verdicts in sample — traffic may be FORWARDED or filters too narrow"
            },
        }),
    )
}

/// F3 — Hubble agent vs relay diagnosis notes.
#[async_trait]
impl Tool for K8sHubbleDiagnose {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.hubble.diagnose".into(),
            name: "Hubble agent/relay diagnosis".into(),
            description: "Check Hubble agent vs relay readiness (cilium pods, hubble-relay, port-forward hints) without requiring live flows.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Read,
            tags: vec!["k8s".into(), "hubble".into(), "cilium".into(), "diagnose".into()],
            input_schema: json!({
                "type": "object",
                "properties": { "context": { "type": "string" } }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let context = args.get("context").and_then(|v| v.as_str());
        let mut notes = Vec::new();
        let mut ready = json!({});

        match kubectl_json(
            context,
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "k8s-app=cilium",
                "-o",
                "json",
            ],
        )
        .await
        {
            Ok(v) => {
                let n = v
                    .get("items")
                    .and_then(|a| a.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                ready
                    .as_object_mut()
                    .unwrap()
                    .insert("cilium_pods".into(), json!(n));
                notes.push(format!("{n} cilium agent pod(s) in kube-system"));
            }
            Err(e) => notes.push(format!("cilium pods: {e}")),
        }

        match kubectl_json(
            context,
            &[
                "get",
                "pods",
                "-n",
                "kube-system",
                "-l",
                "k8s-app=hubble-relay",
                "-o",
                "json",
            ],
        )
        .await
        {
            Ok(v) => {
                let n = v
                    .get("items")
                    .and_then(|a| a.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                ready
                    .as_object_mut()
                    .unwrap()
                    .insert("hubble_relay_pods".into(), json!(n));
                if n == 0 {
                    notes.push(
                        "No hubble-relay pods — use agent-local observe: kubectl -n kube-system exec ds/cilium -- hubble observe"
                            .into(),
                    );
                } else {
                    notes.push(
                        "hubble-relay present — prefer `cilium hubble port-forward` then hubble observe"
                            .into(),
                    );
                }
            }
            Err(e) => notes.push(format!("hubble-relay: {e}")),
        }

        notes.push("Agent path: kubectl -n kube-system exec ds/cilium -- hubble observe --verdict DROPPED".into());
        notes.push("Relay path: cilium hubble port-forward  && hubble observe --server localhost:4245".into());

        ToolResult::success(
            "Hubble diagnosis notes ready",
            json!({
                "format": "HubbleDiagnose",
                "ready": ready,
                "notes": notes,
                "context": context,
            }),
        )
    }
}

/// F4 — Cilium network policy / identity mismatch diagnostics.
#[async_trait]
impl Tool for K8sCiliumPolicyCheck {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.cilium.policy.check".into(),
            name: "Cilium network policy / identity check".into(),
            description: "List CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy and cilium endpoints/identities for mismatch diagnosis.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "k8s".into(),
                "cilium".into(),
                "policy".into(),
                "identity".into(),
                "cni".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "context": { "type": "string" },
                    "namespace": { "type": "string" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let context = args.get("context").and_then(|v| v.as_str());
        let ns = args.get("namespace").and_then(|v| v.as_str());
        let mut policies = Vec::new();
        let mut notes = Vec::new();

        for kind in ["ciliumnetworkpolicies", "ciliumclusterwidenetworkpolicies"] {
            let all: Vec<&str> = if kind.starts_with("ciliumcluster") {
                vec!["get", kind, "-o", "json"]
            } else if let Some(n) = ns {
                vec!["get", kind, "-n", n, "-o", "json"]
            } else {
                vec!["get", kind, "-A", "-o", "json"]
            };
            match kubectl_json(context, &all).await {
                Ok(v) => {
                    if let Some(items) = v.get("items").and_then(|a| a.as_array()) {
                        for p in items {
                            policies.push(json!({
                                "kind": kind,
                                "name": p.pointer("/metadata/name"),
                                "namespace": p.pointer("/metadata/namespace"),
                            }));
                        }
                    }
                }
                Err(e) => notes.push(format!("{kind}: {e}")),
            }
        }

        // Best-effort: cilium identity list via exec
        let mut identities = serde_json::Value::Null;
        if which_ok("cilium").await {
            if let Ok(out) = run_text("cilium", &["identity", "list", "-o", "json"]).await {
                identities = serde_json::from_str(&out).unwrap_or(json!({ "raw": out }));
            }
        }

        ToolResult::success(
            format!("{} Cilium policy object(s)", policies.len()),
            json!({
                "format": "CiliumPolicyCheck",
                "policies": policies,
                "identities": identities,
                "notes": notes,
                "hints": [
                    "Mismatch: policy selector labels vs pod labels / security identities",
                    "hubble observe --verdict DROPPED --pod <pod> for drop reason",
                ],
            }),
        )
    }
}

/// F5 — calicoctl node status
#[async_trait]
impl Tool for K8sCalicoNodeStatus {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.calico.node.status".into(),
            name: "Calico node status".into(),
            description: "Run calicoctl node status (or kubectl get pods calico-node) for CNI health.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Read,
            tags: vec!["k8s".into(), "calico".into(), "cni".into(), "status".into()],
            input_schema: json!({
                "type": "object",
                "properties": { "context": { "type": "string" } }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let context = args.get("context").and_then(|v| v.as_str());
        if which_ok("calicoctl").await {
            match run_text("calicoctl", &["node", "status"]).await {
                Ok(out) => {
                    return ToolResult::success(
                        "calicoctl node status",
                        json!({ "format": "CalicoNodeStatus", "output": out, "via": "calicoctl" }),
                    );
                }
                Err(e) => {
                    // fall through
                    let _ = e;
                }
            }
        }
        match kubectl_json(
            context,
            &[
                "get",
                "pods",
                "-A",
                "-l",
                "k8s-app=calico-node",
                "-o",
                "json",
            ],
        )
        .await
        {
            Ok(v) => {
                let items = v
                    .get("items")
                    .and_then(|a| a.as_array())
                    .cloned()
                    .unwrap_or_default();
                ToolResult::success(
                    format!("{} calico-node pod(s)", items.len()),
                    json!({
                        "format": "CalicoNodeStatus",
                        "via": "kubectl",
                        "pods": items.iter().map(|p| json!({
                            "name": p.pointer("/metadata/name"),
                            "namespace": p.pointer("/metadata/namespace"),
                            "phase": p.pointer("/status/phase"),
                            "node": p.pointer("/spec/nodeName"),
                        })).collect::<Vec<_>>(),
                        "note": "Install calicoctl for full `calicoctl node status` / diags",
                    }),
                )
            }
            Err(e) => ToolResult::error(format!("calico node status: {e}")),
        }
    }
}

/// F6 — calicoctl get networkpolicy pattern search
#[async_trait]
impl Tool for K8sCalicoPolicyPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.calico.policy.pattern".into(),
            name: "Pattern search Calico policies".into(),
            description: "List/filter Calico NetworkPolicy, GlobalNetworkPolicy, WorkloadEndpoint, IPPool (via calicoctl or CRDs) by name fragment.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "k8s".into(),
                "calico".into(),
                "policy".into(),
                "pattern".into(),
                "ippool".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string" },
                    "context": { "type": "string" },
                    "limit": { "type": "integer", "default": 50 }
                },
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let pattern = args
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if pattern.is_empty() {
            return ToolResult::error("pattern is required");
        }
        let context = args.get("context").and_then(|v| v.as_str());
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(50)
            .clamp(1, 200) as usize;
        let mut hits = Vec::new();

        for kind in [
            "networkpolicies.crd.projectcalico.org",
            "globalnetworkpolicies.crd.projectcalico.org",
            "ippools.crd.projectcalico.org",
            "networkpolicies",
        ] {
            let kargs = if kind == "networkpolicies" {
                vec!["get", kind, "-A", "-o", "json"]
            } else {
                vec!["get", kind, "-A", "-o", "json"]
            };
            if let Ok(v) = kubectl_json(context, &kargs).await {
                if let Some(items) = v.get("items").and_then(|a| a.as_array()) {
                    for p in items {
                        let name = p
                            .pointer("/metadata/name")
                            .and_then(|x| x.as_str())
                            .unwrap_or("");
                        let ns = p
                            .pointer("/metadata/namespace")
                            .and_then(|x| x.as_str())
                            .unwrap_or("");
                        let blob = format!("{kind}/{ns}/{name}").to_ascii_lowercase();
                        if blob.contains(&pattern) || name.to_ascii_lowercase().contains(&pattern)
                        {
                            hits.push(json!({
                                "kind": kind,
                                "name": name,
                                "namespace": ns,
                            }));
                        }
                    }
                }
            }
        }
        hits.truncate(limit);
        ToolResult::success(
            format!("{} Calico/K8s policy hit(s) for `{pattern}`", hits.len()),
            json!({ "format": "CalicoPolicyPattern", "pattern": pattern, "hits": hits }),
        )
    }
}

/// F7 — BGP peer status when Calico BGP in use
#[async_trait]
impl Tool for K8sCalicoBgpStatus {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.calico.bgp.status".into(),
            name: "Calico BGP peer status".into(),
            description: "Surface Calico BGPConfiguration / BGPPeer objects and calicoctl node status BGP section when available.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Read,
            tags: vec!["k8s".into(), "calico".into(), "bgp".into(), "cni".into()],
            input_schema: json!({
                "type": "object",
                "properties": { "context": { "type": "string" } }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let context = args.get("context").and_then(|v| v.as_str());
        let mut peers = Vec::new();
        let mut notes = Vec::new();
        for kind in [
            "bgppeers.crd.projectcalico.org",
            "bgpconfigurations.crd.projectcalico.org",
        ] {
            match kubectl_json(context, &["get", kind, "-o", "json"]).await {
                Ok(v) => {
                    if let Some(items) = v.get("items").and_then(|a| a.as_array()) {
                        for p in items {
                            peers.push(json!({
                                "kind": kind,
                                "name": p.pointer("/metadata/name"),
                                "spec": p.get("spec"),
                            }));
                        }
                    }
                }
                Err(e) => notes.push(format!("{kind}: {e}")),
            }
        }
        let mut node_status = None;
        if which_ok("calicoctl").await {
            if let Ok(out) = run_text("calicoctl", &["node", "status"]).await {
                node_status = Some(out);
            }
        }
        ToolResult::success(
            format!("{} BGP-related object(s)", peers.len()),
            json!({
                "format": "CalicoBgpStatus",
                "objects": peers,
                "calicoctl_node_status": node_status,
                "notes": notes,
            }),
        )
    }
}

/// F8 — CNI pod logs collector with redaction
#[async_trait]
impl Tool for K8sCniPodLogs {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.cni.pod_logs".into(),
            name: "Collect CNI pod logs".into(),
            description: "Tail logs from kube-system CNI pods (cilium, calico-node, aws-node) with simple secret redaction.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "k8s".into(),
                "cni".into(),
                "logs".into(),
                "cilium".into(),
                "calico".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "context": { "type": "string" },
                    "flavor": { "type": "string", "description": "cilium | calico | aws-node | auto" },
                    "tail": { "type": "integer", "default": 80 },
                    "namespace": { "type": "string", "default": "kube-system" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let context = args.get("context").and_then(|v| v.as_str());
        let ns = args
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or("kube-system");
        let tail = args
            .get("tail")
            .and_then(|v| v.as_u64())
            .unwrap_or(80)
            .clamp(10, 500);
        let flavor = args
            .get("flavor")
            .and_then(|v| v.as_str())
            .unwrap_or("auto")
            .to_ascii_lowercase();

        let selector = match flavor.as_str() {
            "cilium" => "k8s-app=cilium",
            "calico" => "k8s-app=calico-node",
            "aws-node" | "aws" => "k8s-app=aws-node",
            _ => "", // auto: try common names
        };

        let mut logs = Vec::new();
        let mut pod_names: Vec<String> = Vec::new();

        if !selector.is_empty() {
            if let Ok(v) = kubectl_json(
                context,
                &["get", "pods", "-n", ns, "-l", selector, "-o", "json"],
            )
            .await
            {
                if let Some(items) = v.get("items").and_then(|a| a.as_array()) {
                    for p in items.iter().take(3) {
                        if let Some(n) = p.pointer("/metadata/name").and_then(|x| x.as_str()) {
                            pod_names.push(n.to_string());
                        }
                    }
                }
            }
        } else {
            // auto: list pods and pick CNI-ish names
            if let Ok(v) = kubectl_json(context, &["get", "pods", "-n", ns, "-o", "json"]).await {
                if let Some(items) = v.get("items").and_then(|a| a.as_array()) {
                    for p in items {
                        let n = p
                            .pointer("/metadata/name")
                            .and_then(|x| x.as_str())
                            .unwrap_or("");
                        let nl = n.to_ascii_lowercase();
                        if nl.contains("cilium")
                            || nl.contains("calico")
                            || nl.contains("aws-node")
                            || nl.contains("azure-cni")
                        {
                            pod_names.push(n.to_string());
                            if pod_names.len() >= 3 {
                                break;
                            }
                        }
                    }
                }
            }
        }

        for name in &pod_names {
            let mut kargs = ctx_args(context);
            kargs.extend([
                "logs".into(),
                "-n".into(),
                ns.into(),
                name.clone(),
                format!("--tail={tail}"),
            ]);
            let refs: Vec<&str> = kargs.iter().map(|s| s.as_str()).collect();
            match run_text("kubectl", &refs).await {
                Ok(raw) => {
                    logs.push(json!({
                        "pod": name,
                        "log": redact_secrets(&raw),
                    }));
                }
                Err(e) => logs.push(json!({ "pod": name, "error": e })),
            }
        }

        if logs.is_empty() {
            return ToolResult::error(
                "No CNI pods found for log collection. Try k8s.cni.detect or set flavor=cilium|calico|aws-node.",
            );
        }
        ToolResult::success(
            format!("Collected logs from {} CNI pod(s)", logs.len()),
            json!({
                "format": "CniPodLogs",
                "namespace": ns,
                "pods": pod_names,
                "logs": logs,
            }),
        )
    }
}

fn redact_secrets(s: &str) -> String {
    let mut out = s.to_string();
    // crude redaction for tokens / keys in logs
    for key in ["token=", "password=", "secret=", "AKIA", "Bearer "] {
        if let Some(idx) = out.find(key) {
            let end = (idx + key.len() + 12).min(out.len());
            out.replace_range(idx..end, &format!("{key}***REDACTED***"));
        }
    }
    // cap size
    if out.len() > 24_000 {
        out.truncate(24_000);
        out.push_str("\n…truncated");
    }
    out
}

/// F10 — NetworkPolicy deny path narrative
#[async_trait]
impl Tool for K8sNetworkPolicyDenyNarrative {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.networkpolicy.deny.narrative".into(),
            name: "NetworkPolicy deny path narrative".into(),
            description: "Who might block A→B: list NetworkPolicies selecting source/dest namespaces/pods and combine with optional Hubble drop sample. Best-effort narrative for agents.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "k8s".into(),
                "networkpolicy".into(),
                "deny".into(),
                "path".into(),
                "cni".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "context": { "type": "string" },
                    "from_namespace": { "type": "string" },
                    "from_pod": { "type": "string" },
                    "to_namespace": { "type": "string" },
                    "to_pod": { "type": "string" },
                    "to_port": { "type": "integer" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let context = args.get("context").and_then(|v| v.as_str());
        let from_ns = args.get("from_namespace").and_then(|v| v.as_str());
        let to_ns = args.get("to_namespace").and_then(|v| v.as_str());
        let from_pod = args.get("from_pod").and_then(|v| v.as_str());
        let to_pod = args.get("to_pod").and_then(|v| v.as_str());
        let to_port = args.get("to_port").and_then(|v| v.as_u64());

        let policies = match kubectl_json(context, &["get", "networkpolicies", "-A", "-o", "json"])
            .await
        {
            Ok(v) => v,
            Err(e) => return ToolResult::error(e),
        };

        let mut relevant = Vec::new();
        if let Some(items) = policies.get("items").and_then(|a| a.as_array()) {
            for p in items {
                let ns = p
                    .pointer("/metadata/namespace")
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                let name = p
                    .pointer("/metadata/name")
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                let mut score = 0;
                if let Some(f) = from_ns {
                    if ns == f {
                        score += 2;
                    }
                }
                if let Some(t) = to_ns {
                    if ns == t {
                        score += 2;
                    }
                }
                let blob = p.to_string().to_ascii_lowercase();
                if let Some(fp) = from_pod {
                    if blob.contains(&fp.to_ascii_lowercase()) {
                        score += 1;
                    }
                }
                if let Some(tp) = to_pod {
                    if blob.contains(&tp.to_ascii_lowercase()) {
                        score += 1;
                    }
                }
                if score > 0 || (from_ns.is_none() && to_ns.is_none()) {
                    relevant.push(json!({
                        "namespace": ns,
                        "name": name,
                        "score": score,
                        "pod_selector": p.pointer("/spec/podSelector"),
                        "policy_types": p.pointer("/spec/policyTypes"),
                        "ingress": p.pointer("/spec/ingress"),
                        "egress": p.pointer("/spec/egress"),
                    }));
                }
            }
        }
        relevant.sort_by(|a, b| {
            b.get("score")
                .and_then(|x| x.as_u64())
                .cmp(&a.get("score").and_then(|x| x.as_u64()))
        });
        relevant.truncate(25);

        let narrative = format!(
            "Path {:?} / {:?} → {:?} / {:?} port {:?}: {} NetworkPolicy object(s) may apply. Empty podSelector = all pods in namespace. Default-deny if any policy selects the dest without matching ingress. For Cilium, also run k8s.hubble.observe verdict=DROPPED; for Calico, k8s.calico.policy.pattern.",
            from_ns,
            from_pod,
            to_ns,
            to_pod,
            to_port,
            relevant.len()
        );

        ToolResult::success(
            format!("NetworkPolicy deny narrative ({} policies)", relevant.len()),
            json!({
                "format": "NetworkPolicyDenyNarrative",
                "from": { "namespace": from_ns, "pod": from_pod },
                "to": { "namespace": to_ns, "pod": to_pod, "port": to_port },
                "policies": relevant,
                "narrative": narrative,
                "next_tools": [
                    "k8s.cni.detect",
                    "k8s.hubble.observe",
                    "k8s.calico.policy.pattern",
                    "k8s.cilium.policy.check"
                ],
            }),
        )
    }
}
