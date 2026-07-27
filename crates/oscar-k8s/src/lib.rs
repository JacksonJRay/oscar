//! Kubernetes cluster inventory / pattern discovery / pivot tools.

mod cni;
mod sync;

pub use sync::{k8s_inventory_to_network, sync_and_cache, KubectlK8sSource};

use async_trait::async_trait;
use oscar_core::{Capability, Cloud, PatternQuery, ToolDomain};
use oscar_tools::inventory::{k8s_cache_path, load_json, K8sInventory, K8sResourceEntry};
use oscar_tools::{
    auth_for, discovery_blurb, discovery_tool_result, pattern_properties, scan_k8s_inventory,
    to_tool_result, Tool, ToolContext, ToolMeta, ToolRegistry, ToolResult,
};
use serde_json::json;
use std::sync::Arc;

pub fn register(registry: &mut ToolRegistry) {
    registry.register(Arc::new(K8sContextsList));
    registry.register(Arc::new(K8sResourcesPatternSearch));
    registry.register(Arc::new(K8sPodsPatternSearch));
    registry.register(Arc::new(K8sServicesPatternSearch));
    registry.register(Arc::new(K8sInventorySync));
    registry.register(Arc::new(K8sResourceCreate));
    registry.register(Arc::new(K8sResourceDelete));
    // Track F — CNI / Hubble / Calico
    cni::register_cni(registry);
}

struct K8sContextsList;
struct K8sResourcesPatternSearch;
struct K8sPodsPatternSearch;
struct K8sServicesPatternSearch;
struct K8sInventorySync;
struct K8sResourceCreate;
struct K8sResourceDelete;

async fn load_all_k8s(ctx: &ToolContext, force_sync: bool) -> (Vec<K8sInventory>, bool, Vec<String>) {
    let mut invs = Vec::new();
    let mut partial = false;
    let mut notes = Vec::new();

    // Per-profile cluster caches
    for p in ctx.profiles.list() {
        for c in &p.clusters {
            let key = c.context.as_deref().unwrap_or(&c.name);
            if !force_sync {
                if let Some(inv) = load_json::<K8sInventory>(&k8s_cache_path(&ctx.config_dir, key)) {
                    invs.push(inv);
                    continue;
                }
            }
            match sync_and_cache(&ctx.config_dir, c.context.as_deref(), Some(&p.id)).await {
                Ok(inv) => invs.push(inv),
                Err(e) => {
                    partial = true;
                    notes.push(format!("sync `{key}`: {e}"));
                }
            }
        }
        if let Some(inv) = load_json::<K8sInventory>(&k8s_cache_path(&ctx.config_dir, &p.id)) {
            invs.push(inv);
        }
    }

    // Default local cache / ambient kubectl
    if invs.is_empty() || force_sync {
        match sync_and_cache(&ctx.config_dir, None, None).await {
            Ok(inv) => {
                if !inv.resources.is_empty() || invs.is_empty() {
                    invs.push(inv);
                }
            }
            Err(e) => {
                if invs.is_empty() {
                    partial = true;
                    notes.push(format!("kubectl sync: {e}"));
                }
            }
        }
    } else if let Some(inv) = load_json::<K8sInventory>(&k8s_cache_path(&ctx.config_dir, "default"))
    {
        invs.push(inv);
    }

    if invs.is_empty() {
        partial = true;
        notes.push(
            "No k8s inventory. Run k8s.inventory.sync or ensure kubectl is authenticated."
                .into(),
        );
    }
    (invs, partial, notes)
}

#[async_trait]
impl Tool for K8sContextsList {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.contexts.list".into(),
            name: "List Kubernetes contexts".into(),
            description: "List kubeconfig contexts: oscar profile cluster refs + live `kubectl config get-contexts` when kubectl is available.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s, Cloud::Multi],
            capability: Capability::Read,
            tags: vec!["k8s".into(), "cluster".into(), "context".into(), "list".into(), "kubeconfig".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "live": {
                        "type": "boolean",
                        "default": true,
                        "description": "If true, also run kubectl config get-contexts -o json"
                    }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        use oscar_tools::sync::{run_json_command, which_ok};

        let live = args
            .get("live")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let mut profile_clusters = Vec::new();
        for p in ctx.profiles.list() {
            for c in &p.clusters {
                profile_clusters.push(json!({
                    "profile_id": p.id,
                    "cloud": p.cloud.to_string(),
                    "name": c.name,
                    "context": c.context,
                    "region": c.region,
                }));
            }
        }

        let mut kubectl_contexts = Vec::new();
        let mut current = None;
        let mut kubectl_error = None;
        if live && which_ok("kubectl").await {
            match run_json_command("kubectl", &["config", "view", "-o", "json"]).await {
                Ok(v) => {
                    current = v
                        .pointer("/current-context")
                        .and_then(|c| c.as_str())
                        .map(|s| s.to_string());
                    if let Some(arr) = v.get("contexts").and_then(|c| c.as_array()) {
                        for ctx_obj in arr {
                            let name = ctx_obj
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            let cluster = ctx_obj
                                .pointer("/context/cluster")
                                .and_then(|c| c.as_str())
                                .map(|s| s.to_string());
                            let user = ctx_obj
                                .pointer("/context/user")
                                .and_then(|u| u.as_str())
                                .map(|s| s.to_string());
                            let ns = ctx_obj
                                .pointer("/context/namespace")
                                .and_then(|n| n.as_str())
                                .map(|s| s.to_string());
                            kubectl_contexts.push(json!({
                                "name": name,
                                "cluster": cluster,
                                "user": user,
                                "namespace": ns,
                                "current": current.as_deref() == Some(name.as_str()),
                            }));
                        }
                    }
                }
                Err(e) => kubectl_error = Some(e.to_string()),
            }
        } else if live {
            kubectl_error = Some("kubectl not found on PATH".into());
        }

        if profile_clusters.is_empty() && kubectl_contexts.is_empty() {
            return ToolResult::needs_auth(
                oscar_core::AuthRequest::new(
                    Cloud::K8s,
                    "No cluster contexts found on oscar profiles or kubeconfig.",
                    vec![oscar_core::SecretKind::Kubeconfig],
                )
                .with_hints([
                    "kubectl config get-contexts",
                    "kubectl config current-context",
                    "oscar auth k8s-check",
                ]),
            );
        }

        ToolResult::success(
            format!(
                "{} profile cluster(s), {} kubeconfig context(s){}",
                profile_clusters.len(),
                kubectl_contexts.len(),
                current
                    .as_ref()
                    .map(|c| format!(" · current={c}"))
                    .unwrap_or_default()
            ),
            json!({
                "profile_clusters": profile_clusters,
                "kubectl_contexts": kubectl_contexts,
                "current_context": current,
                "kubectl_error": kubectl_error,
                "attach_hint": "Pin a context on a oscar profile for multi-cluster inventory; ambient kubectl still works for tools that accept --context.",
            }),
        )
    }
}

async fn k8s_pattern(
    args: serde_json::Value,
    ctx: &ToolContext,
    kind_filter: Option<&str>,
) -> ToolResult {
    let q = match PatternQuery::from_args(&args) {
        Ok(q) => q,
        Err(e) => return ToolResult::error(e),
    };
    let kinds_arg = args
        .get("kinds")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_ascii_lowercase()))
                .collect::<Vec<_>>()
        });

    let force = args
        .get("refresh")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let (invs, partial, notes) = load_all_k8s(ctx, force).await;

    let mut merged = oscar_core::DiscoveryResult::empty(&q.pattern, q.mode, "k8s.resources");
    merged.partial = partial;
    merged.notes = notes;

    for inv in invs {
        let mut filtered = inv;
        if let Some(kf) = kind_filter {
            filtered
                .resources
                .retain(|r| r.kind.eq_ignore_ascii_case(kf));
        }
        if let Some(kinds) = &kinds_arg {
            filtered
                .resources
                .retain(|r| kinds.iter().any(|k| r.kind.eq_ignore_ascii_case(k)));
        }
        let mut part = scan_k8s_inventory(&filtered, &q);
        merged.hits.append(&mut part.hits);
    }

    merged.hits.truncate(q.limit);
    to_tool_result(discovery_tool_result(merged.finalize()))
}

#[async_trait]
impl Tool for K8sInventorySync {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.inventory.sync".into(),
            name: "Sync Kubernetes inventory via kubectl".into(),
            description: "Live-fetch pods, services, nodes, namespaces via kubectl into unified K8sInventory cache for pattern search.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s, Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "k8s".into(),
                "sync".into(),
                "inventory".into(),
                "kubectl".into(),
                "cache".into(),
                "cluster".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "context": { "type": "string", "description": "kubectl context name" },
                    "profile_id": { "type": "string" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let context = args.get("context").and_then(|v| v.as_str());
        let profile_id = args.get("profile_id").and_then(|v| v.as_str());
        // If profile given, sync all its clusters
        let mut details = Vec::new();
        let mut total = 0usize;
        if let Some(pid) = profile_id {
            if let Some(p) = ctx.profiles.get(pid) {
                if p.clusters.is_empty() {
                    match sync_and_cache(&ctx.config_dir, context, Some(pid)).await {
                        Ok(inv) => {
                            total += inv.resources.len();
                            details.push(format!(
                                "{}: {} resources (ctx={:?})",
                                pid,
                                inv.resources.len(),
                                inv.context
                            ));
                        }
                        Err(e) => details.push(format!("{pid}: ERROR {e}")),
                    }
                } else {
                    for c in &p.clusters {
                        match sync_and_cache(
                            &ctx.config_dir,
                            c.context.as_deref().or(Some(c.name.as_str())),
                            Some(pid),
                        )
                        .await
                        {
                            Ok(inv) => {
                                total += inv.resources.len();
                                details.push(format!(
                                    "{}/{}: {} resources",
                                    pid,
                                    c.name,
                                    inv.resources.len()
                                ));
                            }
                            Err(e) => details.push(format!("{}/{}: ERROR {e}", pid, c.name)),
                        }
                    }
                }
            } else {
                return ToolResult::error(format!("unknown profile `{pid}`"));
            }
        } else {
            match sync_and_cache(&ctx.config_dir, context, None).await {
                Ok(inv) => {
                    total += inv.resources.len();
                    details.push(format!(
                        "default: {} resources (ctx={:?})",
                        inv.resources.len(),
                        inv.context
                    ));
                }
                Err(e) => {
                    return ToolResult::from_error_text(Cloud::K8s, None, e.to_string());
                }
            }
        }
        ToolResult::success(
            format!("k8s inventory sync: {total} resources"),
            json!({
                "format": "K8sInventory",
                "resources": total,
                "details": details
            }),
        )
    }
}

#[async_trait]
impl Tool for K8sResourcesPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| {
            let mut props = pattern_properties();
            if let Some(obj) = props.as_object_mut() {
                obj.insert(
                    "kinds".into(),
                    json!({
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional resource kinds: pod, service, deployment, ingress, configmap, secret, node, namespace"
                    }),
                );
                obj.insert(
                    "namespace".into(),
                    json!({ "type": "string", "description": "Optional namespace name filter (partial applied via pattern on namespace field when set as pattern scope — prefer kinds+pattern)" }),
                );
            }
            ToolMeta {
                id: "k8s.resources.pattern.search".into(),
                name: "Pattern search Kubernetes resources".into(),
                description: discovery_blurb(
                    "Kubernetes resources (pods, services, deployments, ingress, configmaps, …) by name, label, IP, or namespace fragment — avoids long kubectl-style exploratory queries",
                ),
                domain: ToolDomain::Cluster,
                clouds: vec![Cloud::K8s, Cloud::Multi],
                capability: Capability::Read,
                tags: vec![
                    "k8s".into(),
                    "pattern".into(),
                    "search".into(),
                    "discover".into(),
                    "partial".into(),
                    "glob".into(),
                    "pod".into(),
                    "service".into(),
                    "deployment".into(),
                    "ingress".into(),
                ],
                input_schema: json!({
                    "type": "object",
                    "properties": props,
                    "required": ["pattern"]
                }),
                output_schema: None,
            }
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        k8s_pattern(args, ctx, None).await
    }
}

#[async_trait]
impl Tool for K8sPodsPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.pods.pattern.search".into(),
            name: "Pattern search pods".into(),
            description: discovery_blurb("Kubernetes pods by name, namespace, label, or pod IP"),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Read,
            tags: vec!["k8s".into(), "pod".into(), "pattern".into(), "search".into(), "ip".into()],
            input_schema: json!({
                "type": "object",
                "properties": pattern_properties(),
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        k8s_pattern(args, ctx, Some("pod")).await
    }
}

#[async_trait]
impl Tool for K8sServicesPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.services.pattern.search".into(),
            name: "Pattern search services".into(),
            description: discovery_blurb(
                "Kubernetes services by name, namespace, ClusterIP/LoadBalancer IP fragment",
            ),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "k8s".into(),
                "service".into(),
                "pattern".into(),
                "search".into(),
                "ip".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": pattern_properties(),
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        k8s_pattern(args, ctx, Some("service")).await
    }
}

#[async_trait]
impl Tool for K8sResourceCreate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.resource.create".into(),
            name: "Create Kubernetes resource".into(),
            description: "Apply a Kubernetes YAML/JSON manifest via live kubectl apply -f - (write mode required).".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Write,
            tags: vec!["k8s".into(), "create".into(), "write".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "manifest": { "type": "string" },
                    "context": { "type": "string" }
                },
                "required": ["manifest"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        use oscar_tools::sync::which_ok;
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;

        let manifest = args
            .get("manifest")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if manifest.is_empty() {
            return ToolResult::error("manifest (YAML/JSON) is required");
        }
        if !which_ok("kubectl").await {
            return ToolResult::needs_auth(
                auth_for(Cloud::K8s, "kubectl not found on PATH")
                    .with_hints(["install kubectl", "oscar binaries"]),
            );
        }
        let context = args.get("context").and_then(|v| v.as_str());
        let mut cmd = Command::new("kubectl");
        cmd.arg("apply").arg("-f").arg("-").arg("-o").arg("json");
        if let Some(c) = context {
            cmd.args(["--context", c]);
        }
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return ToolResult::error(format!("spawn kubectl: {e}")),
        };
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = stdin.write_all(manifest.as_bytes()).await {
                return ToolResult::error(format!("write manifest to kubectl: {e}"));
            }
        }
        let out = match child.wait_with_output().await {
            Ok(o) => o,
            Err(e) => return ToolResult::error(format!("kubectl apply: {e}")),
        };
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if !out.status.success() {
            return ToolResult::from_error_text(
                Cloud::K8s,
                None,
                format!("{} {}", stderr.trim(), stdout.trim()),
            );
        }
        let raw: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|_| json!({ "stdout": stdout }));
        let kind = raw
            .pointer("/kind")
            .or_else(|| raw.pointer("/items/0/kind"))
            .and_then(|k| k.as_str())
            .unwrap_or("Resource");
        let name = raw
            .pointer("/metadata/name")
            .or_else(|| raw.pointer("/items/0/metadata/name"))
            .and_then(|n| n.as_str())
            .unwrap_or("—");
        ToolResult::success(
            format!("kubectl apply: {kind}/{name}"),
            json!({
                "cloud": "k8s",
                "action": "apply",
                "kind": kind,
                "name": name,
                "context": context,
                "raw": raw,
            }),
        )
    }
}

#[async_trait]
impl Tool for K8sResourceDelete {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "k8s.resource.delete".into(),
            name: "Delete Kubernetes resource".into(),
            description: "Delete a resource by kind/name/namespace via live kubectl delete (write mode required).".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s],
            capability: Capability::Write,
            tags: vec!["k8s".into(), "delete".into(), "write".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "kind": { "type": "string" },
                    "name": { "type": "string" },
                    "namespace": { "type": "string" },
                    "context": { "type": "string" }
                },
                "required": ["kind", "name"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        use oscar_tools::sync::which_ok;
        use tokio::process::Command;

        let kind = args.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if kind.is_empty() || name.is_empty() {
            return ToolResult::error("kind and name are required");
        }
        if !which_ok("kubectl").await {
            return ToolResult::needs_auth(
                auth_for(Cloud::K8s, "kubectl not found on PATH")
                    .with_hints(["install kubectl", "oscar binaries"]),
            );
        }
        let ns = args.get("namespace").and_then(|v| v.as_str());
        let context = args.get("context").and_then(|v| v.as_str());
        let mut cmd = Command::new("kubectl");
        cmd.arg("delete").arg(kind).arg(name).arg("--wait=false");
        if let Some(n) = ns {
            cmd.args(["-n", n]);
        }
        if let Some(c) = context {
            cmd.args(["--context", c]);
        }
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let out = match cmd.output().await {
            Ok(o) => o,
            Err(e) => return ToolResult::error(format!("spawn kubectl: {e}")),
        };
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if !out.status.success() {
            return ToolResult::from_error_text(
                Cloud::K8s,
                None,
                format!("{stderr} {stdout}"),
            );
        }
        ToolResult::success(
            format!("kubectl delete {kind}/{name}"),
            json!({
                "cloud": "k8s",
                "action": "delete",
                "kind": kind,
                "name": name,
                "namespace": ns,
                "context": context,
                "stdout": stdout,
            }),
        )
    }
}

// Keep type used for docs/examples
#[allow(dead_code)]
fn example_entry() -> K8sResourceEntry {
    K8sResourceEntry {
        kind: "pod".into(),
        name: "api-0".into(),
        namespace: Some("prod".into()),
        labels: vec!["app=api".into()],
        ips: vec!["10.0.4.12".into()],
        extra: vec![],
    }
}
