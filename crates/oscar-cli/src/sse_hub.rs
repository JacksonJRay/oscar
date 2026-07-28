//! Always-on local SSE event bus for oscar (OpenCode-style).
//!
//! Started with the TUI by default. A **watchdog** restarts the accept loop if
//! the listener dies (bind/accept failure, panic recovery via task exit).
//!
//! Endpoints:
//! - `GET  /health` — liveness JSON
//! - `GET  /event`  — Server-Sent Events of serialized `AgentEvent`
//! - `POST /prompt` — queue a user prompt into the host (when wired)
//! - `POST /cancel` — request turn cancel (when wired)

use oscar_core::events::AgentEvent;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

// AgentEvent used by SseHostHooks.event_tx and publish.

/// Default bind for embedded + `oscar serve`.
pub const DEFAULT_SSE_BIND: &str = "127.0.0.1:4096";

#[derive(Debug, Clone)]
pub struct SseHubConfig {
    pub enabled: bool,
    pub bind: String,
    /// Restart accept loop when it exits with an error.
    pub watchdog: bool,
    /// Initial backoff after a crash (doubles up to max).
    pub restart_backoff_ms: u64,
    pub restart_backoff_max_ms: u64,
    /// When true (TUI embed), never write to stderr/stdout — alt-screen corruption.
    /// Bind status goes only through `tracing` + AgentEvent notices.
    pub quiet: bool,
}

impl Default for SseHubConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: std::env::var("OSCAR_SSE_BIND")
                .or_else(|_| std::env::var("OSCAR_SERVE_BIND"))
                .unwrap_or_else(|_| DEFAULT_SSE_BIND.into()),
            watchdog: true,
            restart_backoff_ms: 500,
            restart_backoff_max_ms: 15_000,
            quiet: false,
        }
    }
}

impl SseHubConfig {
    pub fn from_env_and(cfg: &oscar_core::config::SseSettings) -> Self {
        let mut s = Self {
            enabled: cfg.enabled,
            bind: cfg.bind.clone(),
            watchdog: cfg.watchdog,
            restart_backoff_ms: cfg.restart_backoff_ms,
            restart_backoff_max_ms: cfg.restart_backoff_max_ms,
            quiet: false,
        };
        if let Ok(v) = std::env::var("OSCAR_SSE_DISABLE") {
            if matches!(v.as_str(), "1" | "true" | "yes" | "on") {
                s.enabled = false;
            }
        }
        if let Ok(b) = std::env::var("OSCAR_SSE_BIND").or_else(|_| std::env::var("OSCAR_SERVE_BIND"))
        {
            if !b.is_empty() {
                s.bind = b;
            }
        }
        s
    }

    /// Config for the always-on hub embedded beside the Ratatui TUI.
    pub fn for_tui(cfg: &oscar_core::config::SseSettings) -> Self {
        let mut s = Self::from_env_and(cfg);
        s.quiet = true;
        s
    }
}

/// Shared fan-out of AgentEvent JSON lines to SSE clients.
#[derive(Clone)]
pub struct SseHub {
    tx: broadcast::Sender<String>,
    /// Last successfully bound address (updated by watchdog).
    bound: Arc<Mutex<Option<String>>>,
    restarts: Arc<AtomicU64>,
    alive: Arc<AtomicBool>,
}

impl SseHub {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            bound: Arc::new(Mutex::new(None)),
            restarts: Arc::new(AtomicU64::new(0)),
            alive: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn publish(&self, ev: &AgentEvent) {
        if let Ok(line) = serde_json::to_string(ev) {
            let _ = self.tx.send(line);
        }
    }

    #[allow(dead_code)]
    pub fn publish_raw(&self, line: String) {
        let _ = self.tx.send(line);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    pub async fn bound_addr(&self) -> Option<String> {
        self.bound.lock().await.clone()
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub fn restart_count(&self) -> u64 {
        self.restarts.load(Ordering::Relaxed)
    }
}

/// Optional hooks so embedded SSE can drive the TUI host.
#[derive(Clone, Default)]
pub struct SseHostHooks {
    /// User prompts from POST /prompt (unbounded — never block HTTP accept).
    pub user_tx: Option<mpsc::UnboundedSender<String>>,
    /// Cancel signal from POST /cancel.
    pub cancel_tx: Option<mpsc::Sender<()>>,
    /// Optional: publish notices/events into the host fan-out (TUI + SSE).
    pub event_tx: Option<mpsc::Sender<AgentEvent>>,
}

/// Spawn the SSE accept loop under a watchdog. Returns immediately.
///
/// The task runs until `shutdown` is cancelled.
pub fn spawn_sse_watchdog(
    hub: SseHub,
    cfg: SseHubConfig,
    hooks: SseHostHooks,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if !cfg.enabled {
            info!("SSE hub disabled (config/env)");
            return;
        }
        let mut backoff = Duration::from_millis(cfg.restart_backoff_ms.max(50));
        let max_backoff = Duration::from_millis(cfg.restart_backoff_max_ms.max(500));
        let mut first = true;

        loop {
            if shutdown.is_cancelled() {
                hub.alive.store(false, Ordering::Relaxed);
                break;
            }

            let bind = cfg.bind.clone();
            let hub_run = hub.clone();
            let hooks_run = hooks.clone();
            let shutdown_run = shutdown.clone();
            let quiet = cfg.quiet;

            hub.alive.store(false, Ordering::Relaxed);
            let result = run_accept_loop(bind, hub_run, hooks_run, shutdown_run, quiet).await;

            hub.alive.store(false, Ordering::Relaxed);

            if shutdown.is_cancelled() {
                break;
            }

            match result {
                Ok(()) => {
                    // Clean exit (shutdown) — do not restart.
                    break;
                }
                Err(e) => {
                    if !cfg.watchdog {
                        warn!(error = %e, "SSE server stopped (watchdog off)");
                        break;
                    }
                    if !first {
                        hub.restarts.fetch_add(1, Ordering::Relaxed);
                    }
                    first = false;
                    warn!(
                        error = %e,
                        backoff_ms = backoff.as_millis() as u64,
                        restarts = hub.restart_count(),
                        "SSE server failed — watchdog restarting"
                    );
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
        info!("SSE watchdog exited");
    })
}

async fn run_accept_loop(
    preferred_bind: String,
    hub: SseHub,
    hooks: SseHostHooks,
    shutdown: CancellationToken,
    quiet: bool,
) -> Result<(), String> {
    let listener = bind_with_fallback(&preferred_bind).await?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    let bound = addr.to_string();
    *hub.bound.lock().await = Some(bound.clone());
    hub.alive.store(true, Ordering::Relaxed);

    info!(%bound, quiet, "SSE hub listening (GET /event, POST /prompt)");
    // CRITICAL: never eprintln after the TUI has entered the alternate screen —
    // stderr overwrites the Ratatui frame and corrupts chat/input (garbling lines).
    if !quiet {
        eprintln!("oscar SSE  http://{bound}  ·  GET /event  ·  POST /prompt  ·  POST /cancel");
    }

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                return Ok(());
            }
            accepted = listener.accept() => {
                let (socket, peer) = accepted.map_err(|e| format!("accept: {e}"))?;
                let hub_c = hub.clone();
                let hooks_c = hooks.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(socket, peer, hub_c, hooks_c).await {
                        tracing::debug!(%peer, error = %e, "sse connection closed");
                    }
                });
            }
        }
    }
}

/// Bind preferred address; on EADDRINUSE try port+1 .. +20, then ephemeral.
async fn bind_with_fallback(preferred: &str) -> Result<TcpListener, String> {
    match TcpListener::bind(preferred).await {
        Ok(l) => return Ok(l),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            warn!(%preferred, "SSE bind address in use, trying nearby ports");
        }
        Err(e) => return Err(format!("bind {preferred}: {e}")),
    }

    // Parse host:port
    let (host, port) = if let Ok(addr) = preferred.parse::<SocketAddr>() {
        (addr.ip().to_string(), addr.port())
    } else if let Some((h, p)) = preferred.rsplit_once(':') {
        let p: u16 = p.parse().unwrap_or(4096);
        (h.to_string(), p)
    } else {
        ("127.0.0.1".into(), 4096)
    };

    for delta in 1u16..=20 {
        let try_port = port.saturating_add(delta);
        let cand = format!("{host}:{try_port}");
        match TcpListener::bind(&cand).await {
            Ok(l) => {
                warn!(%cand, "SSE bound to alternate port");
                return Ok(l);
            }
            Err(_) => continue,
        }
    }

    // Last resort: ephemeral
    let cand = format!("{host}:0");
    TcpListener::bind(&cand)
        .await
        .map_err(|e| format!("bind fallback {cand}: {e}"))
}

async fn handle_connection(
    mut socket: TcpStream,
    peer: SocketAddr,
    hub: SseHub,
    hooks: SseHostHooks,
) -> Result<(), String> {
    let mut buf = vec![0u8; 64 * 1024];
    let n = socket
        .read(&mut buf)
        .await
        .map_err(|e| format!("read: {e}"))?;
    if n == 0 {
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let (method, path) = {
        let line = req.lines().next().unwrap_or("");
        let mut parts = line.split_whitespace();
        (
            parts.next().unwrap_or("GET").to_string(),
            parts.next().unwrap_or("/").to_string(),
        )
    };
    let body = req
        .split("\r\n\r\n")
        .nth(1)
        .or_else(|| req.split("\n\n").nth(1))
        .unwrap_or("")
        .trim()
        .to_string();

    tracing::debug!(%peer, %method, %path, "sse request");

    if method == "GET" && (path == "/health" || path.starts_with("/health?")) {
        let bound = hub.bound_addr().await.unwrap_or_default();
        let body = serde_json::json!({
            "ok": true,
            "service": "oscar",
            "sse": true,
            "alive": hub.is_alive(),
            "bind": bound,
            "restarts": hub.restart_count(),
        })
        .to_string();
        write_http(&mut socket, 200, "application/json", body.as_bytes()).await?;
        return Ok(());
    }

    if method == "GET" && (path == "/event" || path.starts_with("/event?")) {
        let headers = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/event-stream\r\n",
            "Cache-Control: no-cache\r\n",
            "Connection: keep-alive\r\n",
            "Access-Control-Allow-Origin: *\r\n",
            "\r\n",
        );
        socket
            .write_all(headers.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let _ = socket
            .write_all(b"event: server.connected\ndata: {\"ok\":true,\"service\":\"oscar\"}\n\n")
            .await;
        let mut rx = hub.subscribe();
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Ok(data) => {
                            let frame = format!("data: {data}\n\n");
                            if socket.write_all(frame.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    if socket.write_all(b": heartbeat\n\n").await.is_err() {
                        break;
                    }
                }
            }
        }
        return Ok(());
    }

    if method == "POST" && (path == "/cancel" || path.starts_with("/cancel?")) {
        if let Some(tx) = &hooks.cancel_tx {
            let _ = tx.send(()).await;
        }
        write_http(
            &mut socket,
            200,
            "application/json",
            br#"{"cancelled":true}"#,
        )
        .await?;
        return Ok(());
    }

    if method == "POST" && (path == "/prompt" || path.starts_with("/prompt?")) {
        let text = if body.trim_start().starts_with('{') {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| {
                    v.get("text")
                        .or_else(|| v.get("prompt"))
                        .and_then(|t| t.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or(body)
        } else {
            body
        };
        let text = text.trim().to_string();
        if text.is_empty() {
            write_http(
                &mut socket,
                400,
                "application/json",
                br#"{"error":"empty prompt"}"#,
            )
            .await?;
            return Ok(());
        }
        // Do not echo POST /prompt into the TUI as a notice — chat should only
        // show the normal user turn once the host accepts the prompt.
        let accepted = if let Some(tx) = &hooks.user_tx {
            tx.send(text.clone()).is_ok()
        } else {
            false
        };
        let resp = serde_json::json!({
            "accepted": accepted,
            "preview": text.chars().take(80).collect::<String>(),
            "hint": if accepted {
                "queued for agent host"
            } else {
                "no host wired"
            },
        });
        let body = resp.to_string();
        write_http(
            &mut socket,
            if accepted { 202 } else { 503 },
            "application/json",
            body.as_bytes(),
        )
        .await?;
        return Ok(());
    }

    if method == "GET" && (path == "/" || path.starts_with("/?")) {
        let help = b"oscar SSE hub\n\
GET  /health\n\
GET  /event   (SSE AgentEvent stream)\n\
POST /prompt  (text or {\"text\":\"...\"})\n\
POST /cancel\n";
        write_http(&mut socket, 200, "text/plain; charset=utf-8", help).await?;
        return Ok(());
    }

    write_http(
        &mut socket,
        404,
        "application/json",
        br#"{"error":"not found"}"#,
    )
    .await?;
    Ok(())
}

async fn write_http(
    socket: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        body.len()
    );
    socket
        .write_all(header.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    socket
        .write_all(body)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Dual publisher: every event goes to the TUI channel **and** the SSE hub.
///
/// Prefer this over a fan-out task so a stuck/dead middleman cannot drop
/// host → TUI messages (symptoms: slash notices without replies, chat stuck
/// on “Esc to cancel” with no tokens).
#[derive(Clone)]
pub struct EventBus {
    tui: mpsc::Sender<AgentEvent>,
    hub: SseHub,
}

impl EventBus {
    pub fn new(tui: mpsc::Sender<AgentEvent>, hub: SseHub) -> Self {
        Self { tui, hub }
    }

    pub fn hub(&self) -> &SseHub {
        &self.hub
    }

    pub async fn send(&self, ev: AgentEvent) {
        self.hub.publish(&ev);
        // try_send first so a slow TUI never deadlocks the host forever;
        // fall back to await if buffer is only temporarily full.
        if self.tui.try_send(ev.clone()).is_err() {
            let _ = self.tui.send(ev).await;
        }
    }

    pub fn try_send(&self, ev: AgentEvent) {
        self.hub.publish(&ev);
        let _ = self.tui.try_send(ev);
    }

    /// Clone of the raw TUI sender (for hooks that only need mpsc).
    pub fn tui_sender(&self) -> mpsc::Sender<AgentEvent> {
        self.tui.clone()
    }
}
