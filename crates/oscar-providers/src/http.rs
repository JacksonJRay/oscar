//! Shared HTTP client for LLM providers.
//!
//! Hardened for long-lived SSE streams (Grok Build sampler style):
//! - connect timeout (fail fast on DNS/TLS)
//! - no overall body timeout on the client (streams can run for minutes)
//! - per-request timeout on non-stream `chat`
//! - TCP keepalive + nodelay
//! - clear multi-source error chains

use reqwest::Client;
use std::error::Error as StdError;
use std::sync::OnceLock;
use std::time::Duration;

/// Connect timeout for establishing TLS to the provider.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Overall timeout for non-streaming `chat` requests.
pub const CHAT_REQUEST_TIMEOUT: Duration = Duration::from_secs(180);

/// Idle timeout: no SSE bytes / meaningful chunks for this long → abort.
pub const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Shared reqwest client (connection pool reused across turns).
pub fn shared_client() -> Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                // No default request timeout — SSE streams must stay open.
                // Non-stream calls set `.timeout(CHAT_REQUEST_TIMEOUT)` per-request.
                .pool_idle_timeout(Duration::from_secs(90))
                .pool_max_idle_per_host(4)
                .tcp_keepalive(Duration::from_secs(30))
                .tcp_nodelay(true)
                .user_agent(format!(
                    "oscar/{} (+https://github.com/JacksonJRay/oscar)",
                    env!("CARGO_PKG_VERSION")
                ))
                .build()
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "failed to build shared HTTP client; using default");
                    Client::new()
                })
        })
        .clone()
}

/// Format a reqwest error with the full source chain (TLS/DNS/proxy details).
pub fn format_reqwest_error(e: &reqwest::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut cur: Option<&dyn StdError> = e.source();
    while let Some(err) = cur {
        let s = err.to_string();
        if !parts.iter().any(|p| p == &s) {
            parts.push(s);
        }
        cur = err.source();
    }
    if e.is_connect() {
        parts.push(
            "hint: connect failed — check network/DNS/VPN/firewall; \
             try: curl -sS -o /dev/null -w '%{http_code}' https://api.x.ai/v1"
                .into(),
        );
    } else if e.is_timeout() {
        parts.push("hint: timed out waiting for provider".into());
    } else if e.is_request() {
        parts.push(
            "hint: request build/send failed (TLS, proxy, or HTTP/2); \
             check HTTPS_PROXY / SSL_CERT_FILE if set"
                .into(),
        );
    }
    parts.join(" → ")
}
