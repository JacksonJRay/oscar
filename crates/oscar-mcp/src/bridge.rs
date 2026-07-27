//! Register MCP remote tools as first-class oscar `Tool` implementations.

use crate::client::{McpRemoteTool, SharedMcpClient};
use crate::manager::McpManager;
use async_trait::async_trait;
use oscar_core::{
    infer_mcp_capability, mcp_tool_id, Capability, Cloud, McpServerConfig, ToolDomain,
};
use oscar_tools::{Tool, ToolContext, ToolMeta, ToolRegistry, ToolResult};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::debug;

pub struct McpToolBridge {
    meta: ToolMeta,
    server: String,
    remote_name: String,
    client: SharedMcpClient,
    max_output_bytes: usize,
}

impl McpToolBridge {
    pub fn new(
        server: &str,
        remote: &McpRemoteTool,
        client: SharedMcpClient,
        max_output_bytes: usize,
        server_cfg: Option<&McpServerConfig>,
    ) -> Self {
        let id = mcp_tool_id(server, &remote.name);
        let desc = if remote.description.is_empty() {
            format!("MCP tool `{}` from server `{server}` (via Code Mode search/execute).", remote.name)
        } else {
            format!(
                "{} [mcp:{server}] Mounted as first-class tool; discover via tools_search, not system prompt dump.",
                remote.description
            )
        };
        let capability = server_cfg
            .map(|sc| infer_mcp_capability(&remote.name, &remote.description, sc))
            .unwrap_or(Capability::Read);
        let mut tags = vec![
            "mcp".into(),
            server.into(),
            remote.name.clone(),
            "external".into(),
            "first-class".into(),
        ];
        if matches!(capability, Capability::Write) {
            tags.push("write".into());
            tags.push("mutating".into());
        } else {
            tags.push("read".into());
        }
        let meta = ToolMeta {
            id,
            name: format!("mcp/{}/{}", server, remote.name),
            description: desc,
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi],
            capability,
            tags,
            input_schema: if remote.input_schema.is_null() {
                json!({"type": "object", "properties": {}})
            } else {
                remote.input_schema.clone()
            },
            output_schema: None,
        };
        Self {
            meta,
            server: server.into(),
            remote_name: remote.name.clone(),
            client,
            max_output_bytes,
        }
    }
}

#[async_trait]
impl Tool for McpToolBridge {
    fn meta(&self) -> &ToolMeta {
        &self.meta
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        debug!(
            server = %self.server,
            tool = %self.remote_name,
            "mcp tools/call"
        );
        let mut guard = self.client.lock().await;
        match guard.call_tool(&self.remote_name, args).await {
            Ok(result) => {
                let full = result.to_string();
                let truncated = full.len() > self.max_output_bytes;
                // Grok: spill full payload under session mcp/ folder; model sees truncated.
                let spill_path = if truncated {
                    spill_mcp_result(&ctx.config_dir, &self.server, &self.remote_name, &full)
                } else {
                    None
                };
                let preview = if truncated {
                    let mut t = full;
                    t.truncate(self.max_output_bytes);
                    t.push_str("…[truncated]");
                    t
                } else {
                    full
                };
                // Prefer content array if present (MCP format)
                let summary = result
                    .get("content")
                    .and_then(|c| c.as_array())
                    .and_then(|a| a.first())
                    .and_then(|x| x.get("text"))
                    .and_then(|t| t.as_str())
                    .map(|s| {
                        if s.len() > 200 {
                            format!("{}…", &s[..200])
                        } else {
                            s.to_string()
                        }
                    })
                    .unwrap_or_else(|| format!("mcp {}/{} ok", self.server, self.remote_name));
                let is_error = result
                    .get("isError")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if is_error {
                    ToolResult::error(summary)
                } else {
                    ToolResult::success(
                        summary,
                        json!({
                            "mcp_server": self.server,
                            "mcp_tool": self.remote_name,
                            "truncated": truncated,
                            "full_result_path": spill_path,
                            "result": if truncated {
                                Value::String(preview)
                            } else {
                                result
                            },
                        }),
                    )
                }
            }
            Err(e) => ToolResult::error(format!("mcp {}/{}: {e}", self.server, self.remote_name)),
        }
    }
}

/// Spill large MCP payloads to `artifacts/mcp/<server>/…` (Grok session mcp/ analogue).
fn spill_mcp_result(
    config_dir: &std::path::Path,
    server: &str,
    tool: &str,
    full: &str,
) -> Option<String> {
    let dir = config_dir.join("artifacts").join("mcp").join(server);
    std::fs::create_dir_all(&dir).ok()?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let safe_tool: String = tool
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = dir.join(format!("{ts}_{safe_tool}.json"));
    std::fs::write(&path, full).ok()?;
    Some(path.display().to_string())
}

/// Register all connected MCP tools into the registry.
pub fn register_mcp_tools(registry: &mut ToolRegistry, manager: &McpManager) {
    let max = manager.settings.max_output_bytes;
    for (server, tools) in &manager.tools {
        let Some(client) = manager.clients.get(server) else {
            continue;
        };
        let server_cfg = manager.settings.servers.get(server);
        for remote in tools {
            let bridge =
                McpToolBridge::new(server, remote, Arc::clone(client), max, server_cfg);
            registry.register(Arc::new(bridge));
        }
    }
}

/// Async entry: connect MCP servers from settings and register tools.
pub async fn connect_and_register(
    registry: &mut ToolRegistry,
    settings: oscar_core::McpSettings,
) -> McpManager {
    let mut mgr = McpManager::new(settings);
    mgr.connect_all().await;
    register_mcp_tools(registry, &mgr);
    mgr
}
