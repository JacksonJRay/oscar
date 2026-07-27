//! MCP server configuration (TOML) — tools mount into Code Mode search/execute, not raw context.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Top-level MCP settings under `[mcp]` in config.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpSettings {
    /// Master switch (default true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Cap MCP tool result size returned to the model (bytes).
    #[serde(default = "default_max_output")]
    pub max_output_bytes: usize,
    /// Named servers: `[mcp.servers.<name>]`
    #[serde(default)]
    pub servers: BTreeMap<String, McpServerConfig>,
}

fn default_true() -> bool {
    true
}
fn default_max_output() -> usize {
    20_000
}

impl Default for McpSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            max_output_bytes: default_max_output(),
            servers: BTreeMap::new(),
        }
    }
}

/// One MCP server definition (stdio or HTTP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Transport: stdio (default) | http | sse
    #[serde(default = "default_transport")]
    pub transport: String,
    /// stdio: executable
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// http/sse: base URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "default_startup")]
    pub startup_timeout_sec: u64,
    #[serde(default = "default_tool_timeout")]
    pub tool_timeout_sec: u64,
    /// Per remote tool name → timeout seconds (Grok: `tool_timeouts = { slow_op = 120 }`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tool_timeouts: BTreeMap<String, u64>,
    /// Optional install hint shown in `oscar mcp doctor` / settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_hint: Option<String>,
    /// Default capability for all tools on this server when not overridden:
    /// `"read"` (default) or `"write"`. Write tools still need ReadWrite mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_default: Option<String>,
    /// Per remote tool name → `"read"` | `"write"` override (M10).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tool_capabilities: BTreeMap<String, String>,
    /// OAuth authorization endpoint (optional; for `oscar mcp auth <name>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_authorize_url: Option<String>,
    /// OAuth token endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_token_url: Option<String>,
    /// Public OAuth client id (PKCE public client).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_id: Option<String>,
    /// Space-separated scopes (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_scopes: Option<String>,
    /// OAuth dynamic client registration endpoint (RFC 7591). When set and
    /// `oauth_client_id` is empty, `oscar mcp auth` can register a public client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_registration_url: Option<String>,
}

fn default_transport() -> String {
    "stdio".into()
}
fn default_startup() -> u64 {
    90 // cold npx/uvx downloads often exceed 30s
}
fn default_tool_timeout() -> u64 {
    120
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            transport: default_transport(),
            command: None,
            args: vec![],
            env: BTreeMap::new(),
            url: None,
            headers: BTreeMap::new(),
            startup_timeout_sec: default_startup(),
            tool_timeout_sec: default_tool_timeout(),
            tool_timeouts: BTreeMap::new(),
            install_hint: None,
            capability_default: None,
            tool_capabilities: BTreeMap::new(),
            oauth_authorize_url: None,
            oauth_token_url: None,
            oauth_client_id: None,
            oauth_scopes: None,
            oauth_registration_url: None,
        }
    }
}

impl McpServerConfig {
    /// Timeout for a remote tool name (per-tool override, else server default).
    pub fn timeout_for_tool(&self, remote_tool: &str) -> u64 {
        self.tool_timeouts
            .get(remote_tool)
            .copied()
            .unwrap_or(self.tool_timeout_sec)
            .max(5)
    }
}

/// Infer Read vs Write for an MCP tool (M10).
///
/// Order: explicit `tool_capabilities` → server `capability_default` →
/// keyword inference on name+description → Read.
pub fn infer_mcp_capability(
    tool_name: &str,
    description: &str,
    server: &McpServerConfig,
) -> crate::types::Capability {
    use crate::types::Capability;
    if let Some(cap) = server.tool_capabilities.get(tool_name) {
        return parse_cap_str(cap);
    }
    if let Some(cap) = server.capability_default.as_deref() {
        return parse_cap_str(cap);
    }
    let blob = format!("{tool_name} {description}").to_ascii_lowercase();
    const WRITE_HINTS: &[&str] = &[
        "write",
        "create",
        "delete",
        "remove",
        "update",
        "put",
        "post",
        "patch",
        "mutate",
        "set_",
        "set-",
        "edit",
        "rename",
        "move",
        "mkdir",
        "rm ",
        "unlink",
        "truncate",
        "append",
        "send",
        "publish",
        "deploy",
        "apply",
        "exec",
        "execute_command",
        "run_command",
        "shell",
        "bash",
    ];
    if WRITE_HINTS.iter().any(|h| blob.contains(h)) {
        Capability::Write
    } else {
        Capability::Read
    }
}

fn parse_cap_str(s: &str) -> crate::types::Capability {
    match s.trim().to_ascii_lowercase().as_str() {
        "write" | "rw" | "readwrite" | "read_write" | "mutating" => {
            crate::types::Capability::Write
        }
        _ => crate::types::Capability::Read,
    }
}

impl McpServerConfig {
    pub fn is_stdio(&self) -> bool {
        self.transport.eq_ignore_ascii_case("stdio")
            || (self.command.is_some() && self.url.is_none())
    }

    pub fn validate(&self, name: &str) -> Result<(), String> {
        if self.is_stdio() {
            if self.command.as_ref().map(|c| c.is_empty()).unwrap_or(true) {
                return Err(format!("mcp.servers.{name}: stdio requires `command`"));
            }
        } else if self.url.as_ref().map(|u| u.is_empty()).unwrap_or(true) {
            return Err(format!("mcp.servers.{name}: http/sse requires `url`"));
        }
        Ok(())
    }
}

/// Expand `${VAR}` / `${VAR:-default}` in a string (Grok-style MCP config secrets).
pub fn expand_env_string(s: &str) -> String {
    // Simple single-ref expansion: whole value or embedded ${VAR}
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if let Some(end) = s[i + 2..].find('}') {
                let inner = &s[i + 2..i + 2 + end];
                let (var, default) = if let Some((v, d)) = inner.split_once(":-") {
                    (v, Some(d))
                } else {
                    (inner, None)
                };
                match std::env::var(var) {
                    Ok(val) => out.push_str(&val),
                    Err(_) => {
                        if let Some(d) = default {
                            out.push_str(d);
                        } else {
                            // leave unresolved so doctor can surface misconfig
                            out.push_str(&format!("${{{inner}}}"));
                        }
                    }
                }
                i = i + 2 + end + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Sanitize server + tool name into first-class tool id: `mcp.<server>.<tool>`
pub fn mcp_tool_id(server: &str, tool: &str) -> String {
    let s = sanitize_id_part(server);
    let t = sanitize_id_part(tool);
    format!("mcp.{s}.{t}")
}

fn sanitize_id_part(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Capability;

    #[test]
    fn infer_write_from_tool_name() {
        let sc = McpServerConfig::default();
        assert!(matches!(
            infer_mcp_capability("write_file", "writes a file", &sc),
            Capability::Write
        ));
        assert!(matches!(
            infer_mcp_capability("read_file", "reads a file", &sc),
            Capability::Read
        ));
    }

    #[test]
    fn explicit_override_wins() {
        let mut sc = McpServerConfig::default();
        sc.tool_capabilities
            .insert("danger".into(), "write".into());
        sc.capability_default = Some("read".into());
        assert!(matches!(
            infer_mcp_capability("danger", "safe looking", &sc),
            Capability::Write
        ));
        assert!(matches!(
            infer_mcp_capability("other", "also safe", &sc),
            Capability::Read
        ));
    }

    #[test]
    fn mcp_tool_id_sanitizes() {
        assert_eq!(mcp_tool_id("my server", "write/file"), "mcp.my_server.write_file");
    }

    #[test]
    fn expand_env_string_var_and_default() {
        std::env::set_var("OSCAR_TEST_EXPAND_X", "hello");
        assert_eq!(expand_env_string("pre-${OSCAR_TEST_EXPAND_X}-post"), "pre-hello-post");
        assert_eq!(
            expand_env_string("${OSCAR_TEST_EXPAND_MISSING:-fallback}"),
            "fallback"
        );
        std::env::remove_var("OSCAR_TEST_EXPAND_X");
    }

    #[test]
    fn tool_timeout_override() {
        let mut sc = McpServerConfig::default();
        sc.tool_timeout_sec = 60;
        sc.tool_timeouts.insert("slow".into(), 300);
        assert_eq!(sc.timeout_for_tool("slow"), 300);
        assert_eq!(sc.timeout_for_tool("fast"), 60);
    }
}
