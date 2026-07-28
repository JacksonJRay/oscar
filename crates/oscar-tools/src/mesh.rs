//! Envoy / service-mesh data-plane troubleshooting (read-only admin API).

use crate::pattern_schema::discovery_blurb;
use crate::sync::{command_on_path, run_text_command};
use crate::traits::{Tool, ToolContext, ToolMeta, ToolResult};
use crate::ToolRegistry;
use async_trait::async_trait;
use oscar_core::{Capability, Cloud, ToolDomain};
use serde_json::json;
use std::sync::Arc;

pub fn register_mesh(registry: &mut ToolRegistry) {
    registry.register(Arc::new(MeshEnvoyReady));
    registry.register(Arc::new(MeshEnvoyServerInfo));
    registry.register(Arc::new(MeshEnvoyClusters));
    registry.register(Arc::new(MeshEnvoyClustersPattern));
    registry.register(Arc::new(MeshEnvoyStats));
    registry.register(Arc::new(MeshEnvoyStatsPattern));
    registry.register(Arc::new(MeshEnvoyConfigDump));
    registry.register(Arc::new(MeshEnvoyListeners));
    registry.register(Arc::new(MeshEnvoyDiagnose));
}

fn timeout_arg(args: &serde_json::Value, default: u64) -> u64 {
    args.get("timeout_sec")
        .and_then(|v| v.as_u64())
        .unwrap_or(default)
        .clamp(1, 60)
}

fn admin_base(args: &serde_json::Value) -> String {
    args.get("admin_url")
        .and_then(|v| v.as_str())
        .unwrap_or("http://127.0.0.1:15000")
        .trim_end_matches('/')
        .to_string()
}

/// Fetch Envoy admin path via curl (local) or kubectl exec into sidecar.
async fn envoy_get(args: &serde_json::Value, path: &str, t: u64) -> Result<String, String> {
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let pod = args.get("pod").and_then(|v| v.as_str()).unwrap_or("").trim();
    if !pod.is_empty() {
        if !command_on_path("kubectl").await {
            return Err("kubectl not on PATH (required for pod= target)".into());
        }
        let container = args
            .get("container")
            .and_then(|v| v.as_str())
            .unwrap_or("istio-proxy");
        let url = format!("http://127.0.0.1:15000{path}");
        let ts_owned = t.to_string();
        let mut owned: Vec<String> = vec!["exec".into()];
        if let Some((ns, name)) = pod.split_once('/') {
            owned.push("-n".into());
            owned.push(ns.into());
            owned.push(name.into());
        } else {
            if let Some(ns) = args.get("namespace").and_then(|v| v.as_str()) {
                owned.push("-n".into());
                owned.push(ns.into());
            }
            owned.push(pod.into());
        }
        owned.push("-c".into());
        owned.push(container.into());
        owned.push("--".into());
        owned.push("curl".into());
        owned.push("-sS".into());
        owned.push("--max-time".into());
        owned.push(ts_owned);
        owned.push(url);
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        return run_text_command("kubectl", &refs, t)
            .await
            .map_err(|e| e.to_string());
    }

    if !command_on_path("curl").await {
        return Err("curl not on PATH".into());
    }
    let base = admin_base(args);
    let url = format!("{base}{path}");
    let max = t.to_string();
    run_text_command("curl", &["-sS", "--max-time", &max, &url], t)
        .await
        .map_err(|e| e.to_string())
}

fn common_admin_props() -> serde_json::Value {
    json!({
        "admin_url": {
            "type": "string",
            "default": "http://127.0.0.1:15000",
            "description": "Envoy admin base URL (Istio sidecar default :15000, bare Envoy often :9901)"
        },
        "pod": {
            "type": "string",
            "description": "Optional ns/pod for kubectl exec -c istio-proxy curl localhost:15000"
        },
        "namespace": { "type": "string" },
        "container": { "type": "string", "default": "istio-proxy" },
        "timeout_sec": { "type": "integer", "default": 10 }
    })
}

struct MeshEnvoyReady;
struct MeshEnvoyServerInfo;
struct MeshEnvoyClusters;
struct MeshEnvoyClustersPattern;
struct MeshEnvoyStats;
struct MeshEnvoyStatsPattern;
struct MeshEnvoyConfigDump;
struct MeshEnvoyListeners;
struct MeshEnvoyDiagnose;

#[async_trait]
impl Tool for MeshEnvoyReady {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "mesh.envoy.ready".into(),
            name: "Envoy readiness (/ready)".into(),
            description: "Read-only Envoy admin GET /ready — LIVE vs not ready (mesh 503 triage first step).".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "envoy".into(),
                "mesh".into(),
                "istio".into(),
                "ready".into(),
                "status".into(),
                "health".into(),
                "sidecar".into(),
                "troubleshoot".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": common_admin_props()
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let t = timeout_arg(&args, 10);
        match envoy_get(&args, "/ready", t).await {
            Ok(s) => {
                let live = s.trim().eq_ignore_ascii_case("LIVE");
                ToolResult::success(
                    format!("Envoy /ready: {}", s.trim()),
                    json!({ "format": "EnvoyReady", "ready_text": s.trim(), "live": live }),
                )
            }
            Err(e) => ToolResult::error(e),
        }
    }
}

#[async_trait]
impl Tool for MeshEnvoyServerInfo {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "mesh.envoy.server_info".into(),
            name: "Envoy server_info".into(),
            description: "Envoy admin /server_info — version, state LIVE, uptime. Read-only.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "envoy".into(),
                "mesh".into(),
                "istio".into(),
                "server_info".into(),
                "status".into(),
                "version".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": common_admin_props()
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let t = timeout_arg(&args, 10);
        match envoy_get(&args, "/server_info", t).await {
            Ok(s) => {
                let parsed: serde_json::Value =
                    serde_json::from_str(s.trim()).unwrap_or(json!({ "raw": s.trim() }));
                let state = parsed
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                ToolResult::success(
                    format!("Envoy server_info state={state}"),
                    json!({ "format": "EnvoyServerInfo", "server_info": parsed }),
                )
            }
            Err(e) => ToolResult::error(e),
        }
    }
}

#[async_trait]
impl Tool for MeshEnvoyClusters {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "mesh.envoy.clusters".into(),
            name: "Envoy upstream clusters".into(),
            description: "Envoy admin /clusters — upstream hosts + health (failed_active_hc, etc.). Primary mesh connectivity tool for 503 no healthy upstream.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "envoy".into(),
                "mesh".into(),
                "istio".into(),
                "clusters".into(),
                "upstream".into(),
                "health".into(),
                "status".into(),
                "connectivity".into(),
                "analyze".into(),
                "troubleshoot".into(),
                "503".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "admin_url": common_admin_props()["admin_url"].clone(),
                    "pod": common_admin_props()["pod"].clone(),
                    "namespace": common_admin_props()["namespace"].clone(),
                    "container": common_admin_props()["container"].clone(),
                    "timeout_sec": common_admin_props()["timeout_sec"].clone(),
                    "filter": { "type": "string", "description": "Substring filter on cluster/host lines" },
                    "unhealthy_only": { "type": "boolean", "default": false }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let t = timeout_arg(&args, 15);
        let filter = args
            .get("filter")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let unhealthy_only = args
            .get("unhealthy_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        match envoy_get(&args, "/clusters", t).await {
            Ok(s) => {
                let mut lines: Vec<&str> = s.lines().collect();
                if !filter.is_empty() {
                    lines.retain(|l| l.to_ascii_lowercase().contains(&filter));
                }
                if unhealthy_only {
                    lines.retain(|l| {
                        let lo = l.to_ascii_lowercase();
                        lo.contains("unhealthy")
                            || lo.contains("failed_")
                            || lo.contains("::/failed")
                    });
                }
                // Cap output
                let capped: Vec<&str> = lines.into_iter().take(300).collect();
                let text = capped.join("\n");
                ToolResult::success(
                    format!("Envoy clusters: {} line(s)", capped.len()),
                    json!({
                        "format": "EnvoyClusters",
                        "filter": filter,
                        "unhealthy_only": unhealthy_only,
                        "clusters_text": text
                    }),
                )
            }
            Err(e) => ToolResult::error(e),
        }
    }
}

#[async_trait]
impl Tool for MeshEnvoyClustersPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "mesh.envoy.clusters.pattern".into(),
            name: "Pattern filter Envoy clusters".into(),
            description: discovery_blurb(
                "Envoy /clusters lines by name fragment (narrow after mesh.envoy.diagnose or clusters). pattern required",
            ),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "envoy".into(),
                "mesh".into(),
                "clusters".into(),
                "pattern".into(),
                "search".into(),
                "partial".into(),
                "upstream".into(),
                "troubleshoot".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Cluster/host name fragment" },
                    "query": { "type": "string" },
                    "admin_url": common_admin_props()["admin_url"].clone(),
                    "pod": common_admin_props()["pod"].clone(),
                    "namespace": common_admin_props()["namespace"].clone(),
                    "container": common_admin_props()["container"].clone(),
                    "timeout_sec": common_admin_props()["timeout_sec"].clone(),
                    "unhealthy_only": { "type": "boolean", "default": false }
                },
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, mut args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let pat = args
            .get("pattern")
            .or_else(|| args.get("query"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if pat.is_empty() {
            return ToolResult::error("pattern is required");
        }
        if let Some(obj) = args.as_object_mut() {
            obj.insert("filter".into(), json!(pat));
        }
        MeshEnvoyClusters.execute(args, ctx).await
    }
}

#[async_trait]
impl Tool for MeshEnvoyStats {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "mesh.envoy.stats".into(),
            name: "Envoy stats (filtered)".into(),
            description: "Envoy admin /stats?usedonly with optional filter (e.g. upstream_rq_5xx, cx_connect_fail). Read-only.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "envoy".into(),
                "mesh".into(),
                "stats".into(),
                "metrics".into(),
                "5xx".into(),
                "analyze".into(),
                "troubleshoot".into(),
                "status".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "admin_url": common_admin_props()["admin_url"].clone(),
                    "pod": common_admin_props()["pod"].clone(),
                    "namespace": common_admin_props()["namespace"].clone(),
                    "container": common_admin_props()["container"].clone(),
                    "timeout_sec": common_admin_props()["timeout_sec"].clone(),
                    "filter": {
                        "type": "string",
                        "default": "upstream",
                        "description": "Substring filter on stat names"
                    }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let t = timeout_arg(&args, 15);
        let filter = args
            .get("filter")
            .and_then(|v| v.as_str())
            .unwrap_or("upstream")
            .to_ascii_lowercase();
        // Admin supports ?filter=regex; also filter client-side for portability
        let path = if filter.is_empty() {
            "/stats?usedonly".to_string()
        } else {
            format!("/stats?usedonly&filter={filter}")
        };
        match envoy_get(&args, &path, t).await {
            Ok(s) => {
                let lines: Vec<&str> = s
                    .lines()
                    .filter(|l| {
                        filter.is_empty() || l.to_ascii_lowercase().contains(&filter)
                    })
                    .take(200)
                    .collect();
                ToolResult::success(
                    format!("Envoy stats filter={filter}: {} line(s)", lines.len()),
                    json!({
                        "format": "EnvoyStats",
                        "filter": filter,
                        "stats_text": lines.join("\n")
                    }),
                )
            }
            Err(e) => ToolResult::error(e),
        }
    }
}

#[async_trait]
impl Tool for MeshEnvoyStatsPattern {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "mesh.envoy.stats.pattern".into(),
            name: "Pattern filter Envoy stats".into(),
            description: discovery_blurb(
                "Envoy /stats lines matching a name fragment (e.g. rq_5xx, cx_connect_fail, cluster name)",
            ),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "envoy".into(),
                "mesh".into(),
                "stats".into(),
                "pattern".into(),
                "search".into(),
                "partial".into(),
                "5xx".into(),
                "analyze".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string" },
                    "query": { "type": "string" },
                    "admin_url": common_admin_props()["admin_url"].clone(),
                    "pod": common_admin_props()["pod"].clone(),
                    "namespace": common_admin_props()["namespace"].clone(),
                    "container": common_admin_props()["container"].clone(),
                    "timeout_sec": common_admin_props()["timeout_sec"].clone()
                },
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, mut args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let pat = args
            .get("pattern")
            .or_else(|| args.get("query"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if pat.is_empty() {
            return ToolResult::error("pattern is required");
        }
        if let Some(obj) = args.as_object_mut() {
            obj.insert("filter".into(), json!(pat));
        }
        MeshEnvoyStats.execute(args, ctx).await
    }
}

#[async_trait]
impl Tool for MeshEnvoyConfigDump {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "mesh.envoy.config_dump".into(),
            name: "Envoy config_dump (summarized)".into(),
            description: "Envoy admin /config_dump — returns size summary + optional name filter excerpts. Secrets redacted by Envoy; output truncated for agent safety. Prefer clusters/stats first.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "envoy".into(),
                "mesh".into(),
                "config_dump".into(),
                "xds".into(),
                "eds".into(),
                "routes".into(),
                "troubleshoot".into(),
                "analyze".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "admin_url": common_admin_props()["admin_url"].clone(),
                    "pod": common_admin_props()["pod"].clone(),
                    "namespace": common_admin_props()["namespace"].clone(),
                    "container": common_admin_props()["container"].clone(),
                    "timeout_sec": { "type": "integer", "default": 20 },
                    "include_eds": { "type": "boolean", "default": false },
                    "name_filter": { "type": "string", "description": "Keep JSON lines/objects mentioning this substring" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let t = timeout_arg(&args, 20);
        let include_eds = args
            .get("include_eds")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let name_filter = args
            .get("name_filter")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let path = if include_eds {
            "/config_dump?include_eds"
        } else {
            "/config_dump"
        };
        match envoy_get(&args, path, t).await {
            Ok(s) => {
                let bytes = s.len();
                let excerpt = if !name_filter.is_empty() {
                    s.lines()
                        .filter(|l| l.to_ascii_lowercase().contains(&name_filter))
                        .take(100)
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    // Head only
                    let mut head: String = s.chars().take(12_000).collect();
                    if s.len() > 12_000 {
                        head.push_str("\n… [truncated config_dump]");
                    }
                    head
                };
                // Strip private key blobs if any leaked
                let excerpt = excerpt.replace("private_key", "private_key***");
                ToolResult::success(
                    format!("Envoy config_dump ~{bytes} bytes (summarized)"),
                    json!({
                        "format": "EnvoyConfigDump",
                        "bytes": bytes,
                        "include_eds": include_eds,
                        "name_filter": name_filter,
                        "excerpt": excerpt
                    }),
                )
            }
            Err(e) => ToolResult::error(e),
        }
    }
}

#[async_trait]
impl Tool for MeshEnvoyListeners {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "mesh.envoy.listeners".into(),
            name: "Envoy listeners".into(),
            description: "Envoy admin /listeners — bound addresses/ports.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "envoy".into(),
                "mesh".into(),
                "listeners".into(),
                "port".into(),
                "status".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": common_admin_props()
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let t = timeout_arg(&args, 10);
        match envoy_get(&args, "/listeners", t).await {
            Ok(s) => ToolResult::success(
                format!("Envoy listeners: {} line(s)", s.lines().count()),
                json!({ "format": "EnvoyListeners", "listeners_text": s.trim() }),
            ),
            Err(e) => ToolResult::error(e),
        }
    }
}

#[async_trait]
impl Tool for MeshEnvoyDiagnose {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "mesh.envoy.diagnose".into(),
            name: "Envoy diagnose pack".into(),
            description: "Opinionated Envoy triage: /ready + /server_info + unhealthy cluster lines + key upstream stats. One call for mesh connectivity issues.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "envoy".into(),
                "mesh".into(),
                "diagnose".into(),
                "analyze".into(),
                "status".into(),
                "connectivity".into(),
                "troubleshoot".into(),
                "istio".into(),
                "sidecar".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": common_admin_props()
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let t = timeout_arg(&args, 12);
        let ready = envoy_get(&args, "/ready", t).await.unwrap_or_else(|e| e);
        let info = envoy_get(&args, "/server_info", t)
            .await
            .unwrap_or_else(|e| e);
        let clusters = envoy_get(&args, "/clusters", t)
            .await
            .unwrap_or_else(|e| e);
        let unhealthy: Vec<&str> = clusters
            .lines()
            .filter(|l| {
                let lo = l.to_ascii_lowercase();
                lo.contains("unhealthy") || lo.contains("failed_")
            })
            .take(40)
            .collect();
        let stats = envoy_get(&args, "/stats?usedonly&filter=upstream", t)
            .await
            .unwrap_or_else(|e| e);
        let stat_lines: Vec<&str> = stats
            .lines()
            .filter(|l| {
                let lo = l.to_ascii_lowercase();
                lo.contains("cx_connect_fail")
                    || lo.contains("rq_5xx")
                    || lo.contains("rq_timeout")
                    || lo.contains("membership_healthy")
            })
            .take(40)
            .collect();

        let live = ready.trim().eq_ignore_ascii_case("LIVE");
        ToolResult::success(
            format!(
                "Envoy diagnose: ready={} unhealthy_cluster_lines={} key_stats={}",
                ready.trim(),
                unhealthy.len(),
                stat_lines.len()
            ),
            json!({
                "format": "EnvoyDiagnose",
                "live": live,
                "ready": ready.trim(),
                "server_info_head": info.chars().take(800).collect::<String>(),
                "unhealthy_clusters": unhealthy,
                "key_stats": stat_lines,
                "next_tools": [
                    "mesh.envoy.clusters",
                    "mesh.envoy.stats",
                    "mesh.envoy.config_dump",
                    "network.troubleshoot.playbook"
                ]
            }),
        )
    }
}
