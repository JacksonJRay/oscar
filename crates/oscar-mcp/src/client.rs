//! MCP client: stdio (JSON-RPC + Content-Length) and HTTP/SSE (JSON-RPC POST).

use oscar_core::{expand_env_string, McpServerConfig};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRemoteTool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Value,
}

enum Transport {
    Stdio {
        child: Child,
        stdin: ChildStdin,
        stdout: BufReader<ChildStdout>,
    },
    /// Streamable HTTP / simple JSON-RPC POST (MCP remote servers).
    Http {
        client: reqwest::Client,
        url: String,
        headers: HashMap<String, String>,
        /// Optional session id returned by server (Mcp-Session-Id).
        session_id: Option<String>,
    },
}

pub struct McpClient {
    name: String,
    transport: Transport,
    next_id: u64,
    tool_timeout: Duration,
    tool_timeouts: HashMap<String, Duration>,
}

impl McpClient {
    pub async fn connect(name: &str, cfg: &McpServerConfig) -> Result<Self, String> {
        cfg.validate(name)?;
        let mut tool_timeouts = HashMap::new();
        for (k, secs) in &cfg.tool_timeouts {
            tool_timeouts.insert(k.clone(), Duration::from_secs((*secs).max(5)));
        }
        let tool_timeout = Duration::from_secs(cfg.tool_timeout_sec.max(5));

        let mut client = if cfg.is_stdio() {
            Self::connect_stdio(name, cfg, tool_timeout, tool_timeouts).await?
        } else {
            Self::connect_http(name, cfg, tool_timeout, tool_timeouts).await?
        };

        let init = client
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "oscar", "version": "0.1.0" }
                }),
            )
            .await?;
        debug!(server = %name, ?init, "mcp initialize ok");
        // Capture session id from initialize response if present (some HTTP servers)
        if let Transport::Http {
            session_id: sid, ..
        } = &mut client.transport
        {
            if sid.is_none() {
                if let Some(s) = init.get("sessionId").and_then(|v| v.as_str()) {
                    *sid = Some(s.to_string());
                }
            }
        }
        let _ = client
            .notify("notifications/initialized", json!({}))
            .await;
        Ok(client)
    }

    async fn connect_stdio(
        name: &str,
        cfg: &McpServerConfig,
        tool_timeout: Duration,
        tool_timeouts: HashMap<String, Duration>,
    ) -> Result<Self, String> {
        let cmd = cfg.command.as_ref().unwrap();
        let mut command = Command::new(cmd);
        command
            .args(&cfg.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for (k, v) in &cfg.env {
            command.env(k, v);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("spawn `{cmd}`: {e}"))?;
        let stdin = child.stdin.take().ok_or_else(|| "no stdin".to_string())?;
        let stdout = child.stdout.take().ok_or_else(|| "no stdout".to_string())?;
        Ok(Self {
            name: name.to_string(),
            transport: Transport::Stdio {
                child,
                stdin,
                stdout: BufReader::new(stdout),
            },
            next_id: 1,
            tool_timeout,
            tool_timeouts,
        })
    }

    async fn connect_http(
        name: &str,
        cfg: &McpServerConfig,
        tool_timeout: Duration,
        tool_timeouts: HashMap<String, Duration>,
    ) -> Result<Self, String> {
        let url = cfg
            .url
            .as_ref()
            .ok_or_else(|| format!("server `{name}`: http/sse requires `url`"))?
            .clone();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.startup_timeout_sec.max(30)))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        // Probe with a lightweight GET or just store — initialize will validate.
        let _ = name;
        Ok(Self {
            name: name.to_string(),
            transport: Transport::Http {
                client,
                url,
                headers: cfg.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                session_id: None,
            },
            next_id: 1,
            tool_timeout,
            tool_timeouts,
        })
    }

    pub async fn list_tools(&mut self) -> Result<Vec<McpRemoteTool>, String> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..50 {
            let params = if let Some(c) = &cursor {
                json!({ "cursor": c })
            } else {
                json!({})
            };
            let result = self.request("tools/list", params).await?;
            let tools = result
                .get("tools")
                .and_then(|t| t.as_array())
                .cloned()
                .unwrap_or_default();
            for t in tools {
                let name = t
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                if name.is_empty() {
                    continue;
                }
                let description = t
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                let input_schema = t
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or_else(|| json!({"type": "object", "properties": {}}));
                out.push(McpRemoteTool {
                    name,
                    description,
                    input_schema,
                });
            }
            cursor = result
                .get("nextCursor")
                .and_then(|c| c.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            if cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }

    pub async fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value, String> {
        let timeout = self
            .tool_timeouts
            .get(name)
            .copied()
            .unwrap_or(self.tool_timeout);
        let result = tokio::time::timeout(
            timeout,
            self.request(
                "tools/call",
                json!({
                    "name": name,
                    "arguments": arguments,
                }),
            ),
        )
        .await
        .map_err(|_| {
            format!(
                "tools/call `{name}` timed out after {}s",
                timeout.as_secs()
            )
        })??;
        Ok(result)
    }

    async fn notify(&mut self, method: &str, params: Value) -> Result<(), String> {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        match &mut self.transport {
            Transport::Stdio { stdin, .. } => write_stdio_message(stdin, &msg).await,
            Transport::Http {
                client,
                url,
                headers,
                session_id,
            } => {
                // notifications may return 202/empty
                let mut req = client.post(url.as_str()).json(&msg);
                for (k, v) in headers.iter() {
                    req = req.header(k.as_str(), v.as_str());
                }
                if let Some(sid) = session_id {
                    req = req.header("Mcp-Session-Id", sid.as_str());
                }
                req = req.header("Content-Type", "application/json");
                let _ = req.send().await.map_err(|e| format!("http notify: {e}"))?;
                Ok(())
            }
        }
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        match &mut self.transport {
            Transport::Stdio { stdin, stdout, .. } => {
                write_stdio_message(stdin, &msg).await?;
                loop {
                    let resp = read_stdio_message(stdout).await?;
                    if resp.get("id").and_then(|i| i.as_u64()) == Some(id)
                        || resp.get("id").and_then(|i| i.as_i64()) == Some(id as i64)
                    {
                        if let Some(err) = resp.get("error") {
                            return Err(format!("mcp error: {err}"));
                        }
                        return Ok(resp.get("result").cloned().unwrap_or(json!({})));
                    }
                    debug!(server = %self.name, "skipping mcp message: {}", resp);
                }
            }
            Transport::Http {
                client,
                url,
                headers,
                session_id,
            } => {
                let mut req = client.post(url.as_str()).json(&msg);
                for (k, v) in headers.iter() {
                    req = req.header(k.as_str(), v.as_str());
                }
                if let Some(sid) = session_id.as_ref() {
                    req = req.header("Mcp-Session-Id", sid.as_str());
                }
                req = req
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream");
                let resp = req
                    .send()
                    .await
                    .map_err(|e| format!("http request `{method}`: {e}"))?;
                // Capture session header
                if let Some(sid) = resp.headers().get("mcp-session-id") {
                    if let Ok(s) = sid.to_str() {
                        *session_id = Some(s.to_string());
                    }
                }
                let status = resp.status();
                let ctype = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let body = resp
                    .text()
                    .await
                    .map_err(|e| format!("http body: {e}"))?;
                if !status.is_success() {
                    return Err(format!("http {status}: {body}"));
                }
                let json_body = if ctype.contains("text/event-stream") {
                    // Take last data: JSON line from SSE
                    parse_sse_jsonrpc_result(&body, id)?
                } else {
                    serde_json::from_str::<Value>(&body)
                        .map_err(|e| format!("http json: {e}: {body}"))?
                };
                if let Some(err) = json_body.get("error") {
                    return Err(format!("mcp error: {err}"));
                }
                // Response may be full JSON-RPC or bare result
                if json_body.get("jsonrpc").is_some() {
                    Ok(json_body
                        .get("result")
                        .cloned()
                        .unwrap_or(json!({})))
                } else {
                    Ok(json_body)
                }
            }
        }
    }

    pub fn server_name(&self) -> &str {
        &self.name
    }

    pub async fn shutdown(mut self) {
        if let Transport::Stdio { child, .. } = &mut self.transport {
            let _ = child.kill().await;
        }
    }
}

async fn write_stdio_message(stdin: &mut ChildStdin, msg: &Value) -> Result<(), String> {
    let body = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    stdin
        .write_all(header.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stdin.write_all(&body).await.map_err(|e| e.to_string())?;
    stdin.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn read_stdio_message(stdout: &mut BufReader<ChildStdout>) -> Result<Value, String> {
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        let n = stdout
            .read_line(&mut line)
            .await
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("mcp server closed stdout".into());
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Content-Length:") {
            content_length = rest.trim().parse().ok();
        }
    }
    let len = content_length.ok_or_else(|| "missing Content-Length".to_string())?;
    let mut buf = vec![0u8; len];
    stdout
        .read_exact(&mut buf)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&buf).map_err(|e| format!("mcp json: {e}"))
}

/// Parse SSE body for a JSON-RPC response matching `id`.
fn parse_sse_jsonrpc_result(body: &str, id: u64) -> Result<Value, String> {
    let mut last: Option<Value> = None;
    for line in body.lines() {
        let line = line.trim();
        let data = if let Some(d) = line.strip_prefix("data:") {
            d.trim()
        } else {
            continue;
        };
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(data) {
            if v.get("id").and_then(|i| i.as_u64()) == Some(id)
                || v.get("id").and_then(|i| i.as_i64()) == Some(id as i64)
                || v.get("result").is_some()
            {
                last = Some(v);
            }
        }
    }
    last.ok_or_else(|| format!("sse: no JSON-RPC response for id={id}"))
}

/// Thread-safe handle for tool execution.
pub type SharedMcpClient = std::sync::Arc<Mutex<McpClient>>;

/// Expand `${VAR}` in env map only (legacy helper).
pub fn expand_env_refs(env: &HashMap<String, String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (k, v) in env {
        out.insert(k.clone(), expand_env_string(v));
    }
    out
}

/// Grok-style: expand `${VAR}` / `${VAR:-default}` in command, args, env, url, headers.
pub fn apply_env_expansion(cfg: &mut McpServerConfig) {
    if let Some(cmd) = cfg.command.take() {
        cfg.command = Some(expand_env_string(&cmd));
    }
    cfg.args = cfg.args.iter().map(|a| expand_env_string(a)).collect();
    let mut new_env = std::collections::BTreeMap::new();
    for (k, v) in &cfg.env {
        new_env.insert(k.clone(), expand_env_string(v));
    }
    cfg.env = new_env;
    if let Some(url) = cfg.url.take() {
        cfg.url = Some(expand_env_string(&url));
    }
    let mut new_headers = std::collections::BTreeMap::new();
    for (k, v) in &cfg.headers {
        new_headers.insert(k.clone(), expand_env_string(v));
    }
    cfg.headers = new_headers;
}

/// Doctor: try connect + list tools without keeping process.
pub async fn doctor_server(name: &str, cfg: &McpServerConfig) -> Result<Vec<McpRemoteTool>, String> {
    let mut c = cfg.clone();
    apply_env_expansion(&mut c);
    if let Ok(paths) = oscar_core::Paths::discover() {
        crate::oauth::apply_stored_token(&paths, name, &mut c);
    }
    let timeout = Duration::from_secs(c.startup_timeout_sec.max(5));
    let result = tokio::time::timeout(timeout, async {
        let mut client = McpClient::connect(name, &c).await?;
        let tools = client.list_tools().await?;
        client.shutdown().await;
        Ok::<_, String>(tools)
    })
    .await
    .map_err(|_| format!("startup timeout after {}s", c.startup_timeout_sec))??;
    Ok(result)
}
