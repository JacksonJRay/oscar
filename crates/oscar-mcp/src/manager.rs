//! Session-level MCP manager: connect enabled servers, expose status.

use crate::client::{apply_env_expansion, doctor_server, McpClient, McpRemoteTool, SharedMcpClient};
use oscar_core::{McpServerConfig, McpSettings};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, warn};

#[derive(Debug, Clone, Serialize)]
pub struct McpServerStatus {
    pub name: String,
    pub enabled: bool,
    pub transport: String,
    pub connected: bool,
    pub tool_count: usize,
    pub tools: Vec<String>,
    pub error: Option<String>,
    pub install_hint: Option<String>,
}

pub struct McpManager {
    pub settings: McpSettings,
    /// Live clients by server name.
    pub clients: BTreeMap<String, SharedMcpClient>,
    /// Cached tool defs per server.
    pub tools: BTreeMap<String, Vec<McpRemoteTool>>,
    pub statuses: Vec<McpServerStatus>,
}

impl McpManager {
    pub fn new(settings: McpSettings) -> Self {
        Self {
            settings,
            clients: BTreeMap::new(),
            tools: BTreeMap::new(),
            statuses: vec![],
        }
    }

    /// Connect all enabled servers (best-effort; failures recorded in status).
    pub async fn connect_all(&mut self) {
        self.statuses.clear();
        self.clients.clear();
        self.tools.clear();
        if !self.settings.enabled {
            debug!("mcp master switch disabled");
            return;
        }
        let servers: Vec<(String, McpServerConfig)> = self
            .settings
            .servers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (name, mut cfg) in servers {
            if !cfg.enabled {
                self.statuses.push(McpServerStatus {
                    name: name.clone(),
                    enabled: false,
                    transport: cfg.transport.clone(),
                    connected: false,
                    tool_count: 0,
                    tools: vec![],
                    error: Some("disabled in config".into()),
                    install_hint: cfg.install_hint.clone(),
                });
                continue;
            }
            apply_env_expansion(&mut cfg);
            // Inject stored OAuth token if present (never logs the secret).
            if let Ok(paths) = oscar_core::Paths::discover() {
                crate::oauth::apply_stored_token(&paths, &name, &mut cfg);
            }
            let startup = std::time::Duration::from_secs(cfg.startup_timeout_sec.max(5));
            let connect_result = tokio::time::timeout(startup, async {
                let mut client = McpClient::connect(&name, &cfg).await?;
                let tools = client.list_tools().await?;
                Ok::<_, String>((client, tools))
            })
            .await;
            match connect_result {
                Ok(Ok((client, tools))) => {
                    let names: Vec<String> = tools.iter().map(|t| t.name.clone()).collect();
                    let count = tools.len();
                    debug!(server = %name, count, "mcp tools listed");
                    self.tools.insert(name.clone(), tools);
                    self.clients
                        .insert(name.clone(), Arc::new(Mutex::new(client)));
                    self.statuses.push(McpServerStatus {
                        name,
                        enabled: true,
                        transport: cfg.transport,
                        connected: true,
                        tool_count: count,
                        tools: names,
                        error: None,
                        install_hint: cfg.install_hint,
                    });
                }
                Ok(Err(e)) => {
                    warn!(server = %name, %e, "mcp connect/list failed");
                    self.statuses.push(McpServerStatus {
                        name,
                        enabled: true,
                        transport: cfg.transport.clone(),
                        connected: false,
                        tool_count: 0,
                        tools: vec![],
                        error: Some(e),
                        install_hint: cfg.install_hint,
                    });
                }
                Err(_) => {
                    let e = format!(
                        "startup timeout after {}s (cold npx/uvx may need higher startup_timeout_sec)",
                        cfg.startup_timeout_sec
                    );
                    warn!(server = %name, %e, "mcp connect timed out");
                    self.statuses.push(McpServerStatus {
                        name,
                        enabled: true,
                        transport: cfg.transport.clone(),
                        connected: false,
                        tool_count: 0,
                        tools: vec![],
                        error: Some(e),
                        install_hint: cfg.install_hint,
                    });
                }
            }
        }
    }

    pub async fn doctor_all(settings: &McpSettings) -> Vec<McpServerStatus> {
        let mut out = Vec::new();
        for (name, cfg) in &settings.servers {
            if !cfg.enabled {
                out.push(McpServerStatus {
                    name: name.clone(),
                    enabled: false,
                    transport: cfg.transport.clone(),
                    connected: false,
                    tool_count: 0,
                    tools: vec![],
                    error: Some("disabled".into()),
                    install_hint: cfg.install_hint.clone(),
                });
                continue;
            }
            match doctor_server(name, cfg).await {
                Ok(tools) => {
                    let names: Vec<_> = tools.iter().map(|t| t.name.clone()).collect();
                    out.push(McpServerStatus {
                        name: name.clone(),
                        enabled: true,
                        transport: cfg.transport.clone(),
                        connected: true,
                        tool_count: tools.len(),
                        tools: names,
                        error: None,
                        install_hint: cfg.install_hint.clone(),
                    });
                }
                Err(e) => out.push(McpServerStatus {
                    name: name.clone(),
                    enabled: true,
                    transport: cfg.transport.clone(),
                    connected: false,
                    tool_count: 0,
                    tools: vec![],
                    error: Some(e),
                    install_hint: cfg.install_hint.clone(),
                }),
            }
        }
        out
    }
}
