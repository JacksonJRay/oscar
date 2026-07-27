//! Dynamic third-party tools (plan open follow-up: plugin model).
//!
//! Load `~/.config/oscar/plugins/*.toml` (and project `.oscar/plugins/*.toml`) as
//! first-class tools. Plugins run a local command; stdout is the result (redacted
//! by the agent layer). Write capability is honored by the mode gate.

use crate::traits::{Tool, ToolContext, ToolMeta, ToolResult};
use crate::ToolRegistry;
use async_trait::async_trait;
use oscar_core::{Capability, Cloud, Paths, ToolDomain};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tracing::{info, warn};

#[derive(Debug, Clone, Deserialize)]
pub struct PluginManifest {
    /// Stable tool id, e.g. `plugin.site.healthcheck`
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// dns | network | access | account | cluster | infra | meta
    #[serde(default = "default_domain")]
    pub domain: String,
    #[serde(default = "default_clouds")]
    pub clouds: Vec<String>,
    /// read | write
    #[serde(default = "default_read")]
    pub capability: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Executable
    pub command: String,
    /// Arguments; `{{key}}` substituted from tools_execute arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Working directory (optional).
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_sec: u64,
    /// Optional JSON Schema object for input (properties only is fine).
    #[serde(default)]
    pub input_schema: Option<Value>,
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// When true, plugin is skipped.
    #[serde(default)]
    pub disabled: bool,
}

fn default_domain() -> String {
    "meta".into()
}
fn default_clouds() -> Vec<String> {
    vec!["multi".into()]
}
fn default_read() -> String {
    "read".into()
}
fn default_timeout() -> u64 {
    60
}

fn parse_domain(s: &str) -> ToolDomain {
    match s.to_ascii_lowercase().as_str() {
        "dns" => ToolDomain::Dns,
        "network" => ToolDomain::Network,
        "access" => ToolDomain::Access,
        "account" => ToolDomain::Account,
        "cluster" => ToolDomain::Cluster,
        "infra" => ToolDomain::Infra,
        _ => ToolDomain::Meta,
    }
}

fn parse_cloud(s: &str) -> Option<Cloud> {
    match s.to_ascii_lowercase().as_str() {
        "aws" => Some(Cloud::Aws),
        "gcp" => Some(Cloud::Gcp),
        "azure" => Some(Cloud::Azure),
        "k8s" | "kubernetes" => Some(Cloud::K8s),
        "multi" => Some(Cloud::Multi),
        _ => None,
    }
}

fn parse_cap(s: &str) -> Capability {
    match s.to_ascii_lowercase().as_str() {
        "write" | "rw" | "readwrite" => Capability::Write,
        _ => Capability::Read,
    }
}

/// Discover plugin dirs: user config + walk-up `.oscar/plugins` from cwd.
pub fn plugin_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(p) = Paths::discover() {
        dirs.push(p.config_dir.join("plugins"));
    }
    // project walk-up
    if let Ok(mut cur) = std::env::current_dir() {
        for _ in 0..8 {
            let cand = cur.join(".oscar").join("plugins");
            if cand.is_dir() {
                dirs.push(cand);
            }
            if !cur.pop() {
                break;
            }
        }
    }
    dirs
}

pub fn load_plugin_manifests() -> Vec<(PathBuf, PluginManifest)> {
    let mut out = Vec::new();
    for dir in plugin_dirs() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let path = ent.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(raw) => match toml::from_str::<PluginManifest>(&raw) {
                    Ok(m) if !m.disabled && !m.id.is_empty() && !m.command.is_empty() => {
                        out.push((path, m));
                    }
                    Ok(_) => warn!(?path, "plugin skipped (disabled or incomplete)"),
                    Err(e) => warn!(?path, error = %e, "plugin parse failed"),
                },
                Err(e) => warn!(?path, error = %e, "plugin read failed"),
            }
        }
    }
    out
}

/// Register all discovered plugins into the registry.
pub fn register_plugins(registry: &mut ToolRegistry) -> usize {
    let mut n = 0;
    for (path, m) in load_plugin_manifests() {
        let id = m.id.clone();
        if !id.starts_with("plugin.") {
            warn!(%id, "plugin id should start with plugin. — registering anyway");
        }
        registry.register(Arc::new(PluginTool::new(m, path)));
        n += 1;
        info!(%id, "registered plugin tool");
    }
    n
}

struct PluginTool {
    meta: ToolMeta,
    command: String,
    args: Vec<String>,
    cwd: Option<String>,
    timeout_sec: u64,
    env: std::collections::BTreeMap<String, String>,
    source: PathBuf,
}

impl PluginTool {
    fn new(m: PluginManifest, source: PathBuf) -> Self {
        let mut tags = m.tags;
        if !tags.iter().any(|t| t == "plugin") {
            tags.push("plugin".into());
        }
        tags.push("external".into());
        let clouds: Vec<Cloud> = m
            .clouds
            .iter()
            .filter_map(|c| parse_cloud(c))
            .collect();
        let clouds = if clouds.is_empty() {
            vec![Cloud::Multi]
        } else {
            clouds
        };
        let input_schema = m.input_schema.unwrap_or_else(|| {
            json!({
                "type": "object",
                "properties": {
                    "args": {
                        "type": "string",
                        "description": "Optional extra free-form argument appended to the plugin command"
                    }
                }
            })
        });
        let meta = ToolMeta {
            id: m.id.clone(),
            name: m.name.unwrap_or_else(|| m.id.clone()),
            description: m.description.unwrap_or_else(|| {
                format!(
                    "Plugin tool from {} — runs local command `{}`",
                    source.display(),
                    m.command
                )
            }),
            domain: parse_domain(&m.domain),
            clouds,
            capability: parse_cap(&m.capability),
            tags,
            input_schema,
            output_schema: None,
        };
        Self {
            meta,
            command: m.command,
            args: m.args,
            cwd: m.cwd,
            timeout_sec: m.timeout_sec.max(1),
            env: m.env,
            source,
        }
    }
}

fn substitute(template: &str, args: &Value) -> String {
    let mut out = template.to_string();
    if let Some(obj) = args.as_object() {
        for (k, v) in obj {
            let needle = format!("{{{{{k}}}}}");
            let repl = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                Value::Null => String::new(),
                other => other.to_string(),
            };
            out = out.replace(&needle, &repl);
        }
    }
    out
}

#[async_trait]
impl Tool for PluginTool {
    fn meta(&self) -> &ToolMeta {
        &self.meta
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        if ctx.cancel.is_cancelled() {
            return ToolResult::error("cancelled");
        }
        let mut cmd = Command::new(&self.command);
        for a in &self.args {
            cmd.arg(substitute(a, &args));
        }
        if let Some(extra) = args.get("args").and_then(|v| v.as_str()) {
            if !extra.is_empty() {
                cmd.arg(extra);
            }
        }
        if let Some(cwd) = &self.cwd {
            cmd.current_dir(Path::new(cwd));
        }
        for (k, v) in &self.env {
            cmd.env(k, oscar_core::expand_env_string(v));
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let timeout = Duration::from_secs(self.timeout_sec);
        let run = async {
            let out = cmd
                .output()
                .await
                .map_err(|e| format!("spawn `{}`: {e}", self.command))?;
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            if !out.status.success() {
                return Err(format!(
                    "plugin exit {}: {} {}",
                    out.status.code().unwrap_or(-1),
                    stderr.trim(),
                    stdout.trim()
                ));
            }
            Ok((stdout, stderr))
        };
        match tokio::time::timeout(timeout, run).await {
            Ok(Ok((stdout, stderr))) => {
                let summary: String = stdout.lines().next().unwrap_or("plugin ok").chars().take(200).collect();
                ToolResult::success(
                    summary,
                    json!({
                        "plugin_id": self.meta.id,
                        "source": self.source.display().to_string(),
                        "stdout": stdout,
                        "stderr": stderr,
                    }),
                )
            }
            Ok(Err(e)) => ToolResult::error(e),
            Err(_) => ToolResult::error(format!(
                "plugin `{}` timed out after {}s",
                self.meta.id, self.timeout_sec
            )),
        }
    }
}

/// Example plugin body for docs.
pub fn example_plugin_toml() -> &'static str {
    r#"# ~/.config/oscar/plugins/example-echo.toml
id = "plugin.example.echo"
name = "Example echo plugin"
description = "Demo plugin: echoes a message via printf"
domain = "meta"
clouds = ["multi"]
capability = "read"
tags = ["example", "demo"]
command = "printf"
args = ["%s", "{{message}}"]
timeout_sec = 10

[input_schema]
type = "object"
properties = { message = { type = "string", description = "Text to echo" } }
required = ["message"]
"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn substitute_args() {
        let v = json!({"message": "hi", "n": 3});
        assert_eq!(substitute("say {{message}} x{{n}}", &v), "say hi x3");
    }

    #[test]
    fn parse_manifest() {
        let m: PluginManifest = toml::from_str(
            r#"
id = "plugin.t"
command = "echo"
args = ["hi"]
"#,
        )
        .unwrap();
        assert_eq!(m.id, "plugin.t");
        assert_eq!(m.timeout_sec, 60);
    }

    #[test]
    fn load_from_dir() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("p.toml");
        std::fs::write(
            &p,
            r#"
id = "plugin.test.load"
command = "true"
"#,
        )
        .unwrap();
        // load_plugin_manifests walks config dirs; unit-test parse only
        let raw = std::fs::read_to_string(&p).unwrap();
        let m: PluginManifest = toml::from_str(&raw).unwrap();
        assert_eq!(m.command, "true");
    }
}
