//! MCP OAuth token storage + PKCE authorization-code flow.
//!
//! Tokens live in `~/.config/oscar/mcp_credentials.json` (mode 0600 on Unix).
//! Never injected into chat — only used as HTTP Authorization headers.

use oscar_core::{McpServerConfig, Paths};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct McpCredentialsFile {
    /// server name → token record
    #[serde(default)]
    pub servers: BTreeMap<String, McpTokenRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTokenRecord {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Token endpoint used for refresh (captured at login).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default)]
    pub updated_at: u64,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn credentials_path(paths: &Paths) -> &Path {
    &paths.mcp_credentials_file
}

pub fn load_credentials(paths: &Paths) -> McpCredentialsFile {
    let path = credentials_path(paths);
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => McpCredentialsFile::default(),
    }
}

pub fn save_credentials(paths: &Paths, file: &McpCredentialsFile) -> Result<(), String> {
    paths.ensure().map_err(|e| e.to_string())?;
    let path = credentials_path(paths);
    let raw = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    fs::write(path, raw).map_err(|e| format!("write credentials: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn get_access_token(paths: &Paths, server: &str) -> Option<String> {
    let file = load_credentials(paths);
    let rec = file.servers.get(server)?;
    if let Some(exp) = rec.expires_at {
        if now_unix() + 30 >= exp {
            warn!(server, "mcp oauth token expired or near expiry");
        }
    }
    Some(rec.access_token.clone())
}

/// Return a valid access token, refreshing with `refresh_token` when expired.
/// Prefer this over `get_access_token` on the connect path.
pub fn get_valid_access_token(paths: &Paths, server: &str) -> Option<String> {
    let file = load_credentials(paths);
    let rec = file.servers.get(server)?.clone();
    let needs_refresh = rec
        .expires_at
        .map(|e| now_unix() + 60 >= e)
        .unwrap_or(false);
    if !needs_refresh {
        return Some(rec.access_token);
    }
    let refresh = rec.refresh_token.as_deref()?;
    let token_url = rec.token_url.as_deref()?;
    let client_id = rec.client_id.as_deref()?;
    match refresh_access_token_blocking(token_url, client_id, refresh) {
        Ok((access, new_refresh, expires_in, scope)) => {
            let _ = set_access_token_full(
                paths,
                server,
                &access,
                new_refresh.or(rec.refresh_token.clone()),
                expires_in,
                scope.or(rec.scope.clone()),
                Some(token_url.to_string()),
                Some(client_id.to_string()),
            );
            info!(server, "refreshed mcp oauth access token");
            Some(access)
        }
        Err(e) => {
            warn!(server, error = %e, "mcp oauth refresh failed; using stored token");
            Some(rec.access_token)
        }
    }
}

fn refresh_access_token_blocking(
    token_url: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<(String, Option<String>, Option<u64>, Option<String>), String> {
    // Blocking reqwest so apply_stored_token stays sync on connect.
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    let resp = client
        .post(token_url)
        .form(&form)
        .send()
        .map_err(|e| format!("refresh request: {e}"))?;
    let status = resp.status();
    let body = resp.text().map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("refresh {status}: {body}"));
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("refresh json: {e}"))?;
    let access = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| "no access_token in refresh response".to_string())?
        .to_string();
    let new_refresh = v
        .get("refresh_token")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string());
    let expires_in = v.get("expires_in").and_then(|e| e.as_u64());
    let scope = v
        .get("scope")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    Ok((access, new_refresh, expires_in, scope))
}

pub fn set_access_token(
    paths: &Paths,
    server: &str,
    access_token: &str,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
) -> Result<(), String> {
    set_access_token_full(
        paths,
        server,
        access_token,
        refresh_token,
        expires_in,
        scope,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn set_access_token_full(
    paths: &Paths,
    server: &str,
    access_token: &str,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
    token_url: Option<String>,
    client_id: Option<String>,
) -> Result<(), String> {
    let mut file = load_credentials(paths);
    // Preserve prior refresh/token_url/client_id when not re-supplied
    let prior = file.servers.get(server).cloned();
    file.servers.insert(
        server.to_string(),
        McpTokenRecord {
            access_token: access_token.to_string(),
            refresh_token: refresh_token.or_else(|| prior.as_ref().and_then(|p| p.refresh_token.clone())),
            token_type: Some("Bearer".into()),
            expires_at: expires_in.map(|s| now_unix() + s),
            scope: scope.or_else(|| prior.as_ref().and_then(|p| p.scope.clone())),
            token_url: token_url.or_else(|| prior.as_ref().and_then(|p| p.token_url.clone())),
            client_id: client_id.or_else(|| prior.as_ref().and_then(|p| p.client_id.clone())),
            updated_at: now_unix(),
        },
    );
    save_credentials(paths, &file)
}

pub fn clear_token(paths: &Paths, server: &str) -> Result<bool, String> {
    let mut file = load_credentials(paths);
    let removed = file.servers.remove(server).is_some();
    if removed {
        save_credentials(paths, &file)?;
    }
    Ok(removed)
}

/// Inject stored Bearer token into server headers if not already set.
/// Refreshes expired tokens when refresh_token + token_url + client_id are stored.
pub fn apply_stored_token(paths: &Paths, server: &str, cfg: &mut McpServerConfig) {
    if cfg
        .headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("authorization"))
    {
        return;
    }
    // Prefer config oauth endpoints for refresh when credentials lack them
    if let Some(rec) = load_credentials(paths).servers.get(server) {
        if rec.token_url.is_none() || rec.client_id.is_none() {
            if let (Some(tu), Some(cid)) =
                (cfg.oauth_token_url.as_ref(), cfg.oauth_client_id.as_ref())
            {
                let _ = set_access_token_full(
                    paths,
                    server,
                    &rec.access_token,
                    rec.refresh_token.clone(),
                    rec.expires_at.map(|e| e.saturating_sub(now_unix())),
                    rec.scope.clone(),
                    Some(tu.clone()),
                    Some(cid.clone()),
                );
            }
        }
    }
    if let Some(tok) = get_valid_access_token(paths, server) {
        cfg.headers
            .insert("Authorization".into(), format!("Bearer {tok}"));
        info!(server, "applied stored mcp oauth token");
    }
}

fn b64url_no_pad(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
    }
    out
}

fn random_urlsafe(n: usize) -> String {
    let mut buf = vec![0u8; n];
    // Prefer OS entropy; fall back to time-based if unavailable.
    if getrandom_fill(&mut buf).is_err() {
        let t = now_unix().to_le_bytes();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = t[i % t.len()].wrapping_add(i as u8).wrapping_mul(17);
        }
    }
    b64url_no_pad(&buf)
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), ()> {
    // Use /dev/urandom on Unix without extra crate.
    #[cfg(unix)]
    {
        use std::fs::File;
        let mut f = File::open("/dev/urandom").map_err(|_| ())?;
        f.read_exact(buf).map_err(|_| ())?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        let _ = buf;
        Err(())
    }
}

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    b64url_no_pad(&digest)
}

fn open_browser(url: &str) -> Result<(), String> {
    let cmds: &[&[&str]] = if cfg!(target_os = "macos") {
        &[&["open", url]]
    } else if cfg!(target_os = "windows") {
        &[&["cmd", "/C", "start", "", url]]
    } else {
        &[&["xdg-open", url], &["gio", "open", url]]
    };
    for c in cmds {
        if Command::new(c[0]).args(&c[1..]).spawn().is_ok() {
            return Ok(());
        }
    }
    Err("could not open browser — open the URL printed above manually".into())
}

/// Best-effort RFC 7591 dynamic client registration for public PKCE clients.
pub async fn register_oauth_client(
    registration_url: &str,
    redirect_uris: &[String],
    client_name: &str,
) -> Result<String, String> {
    let client = reqwest::Client::new();
    let body = json!({
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "native",
    });
    let resp = client
        .post(registration_url)
        .json(&body)
        .header("Content-Type", "application/json")
        .send()
        .await
        .map_err(|e| format!("registration request: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("registration {status}: {text}"));
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("registration json: {e}: {text}"))?;
    v.get("client_id")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("no client_id in registration response: {text}"))
}

/// Run PKCE authorization-code flow for a configured MCP server.
/// Requires oauth_authorize_url, oauth_token_url; client_id or oauth_registration_url.
pub async fn run_oauth_login(
    paths: &Paths,
    server: &str,
    cfg: &McpServerConfig,
) -> Result<String, String> {
    let authorize = cfg
        .oauth_authorize_url
        .as_deref()
        .ok_or_else(|| {
            "oauth_authorize_url not set — set in TOML or use: oscar mcp set-token <name> --token …"
                .to_string()
        })?;
    let token_url = cfg
        .oauth_token_url
        .as_deref()
        .ok_or_else(|| "oauth_token_url not set".to_string())?;

    // Bind early so we can advertise redirect_uri in DCR
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind callback: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let client_id = if let Some(cid) = cfg.oauth_client_id.as_deref().filter(|s| !s.is_empty()) {
        cid.to_string()
    } else if let Some(reg) = cfg.oauth_registration_url.as_deref() {
        info!(server, "dynamic client registration via {reg}");
        register_oauth_client(reg, &[redirect.clone()], &format!("oscar-{server}")).await?
    } else {
        return Err(
            "oauth_client_id not set (and no oauth_registration_url for dynamic registration)"
                .into(),
        );
    };

    let verifier = random_urlsafe(32);
    let challenge = pkce_challenge(&verifier);
    let state = random_urlsafe(16);

    let mut auth = format!(
        "{authorize}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}",
        urlencoding_encode(&client_id),
        urlencoding_encode(&redirect),
        urlencoding_encode(&challenge),
        urlencoding_encode(&state),
    );
    if let Some(scopes) = cfg.oauth_scopes.as_deref() {
        auth.push_str(&format!("&scope={}", urlencoding_encode(scopes)));
    }

    println!("Open this URL to authorize MCP server `{server}`:\n  {auth}\n");
    if let Err(e) = open_browser(&auth) {
        eprintln!("note: {e}");
    }
    println!("Waiting for browser callback on {redirect} …");

    // Blocking accept on a worker thread so we can keep async runtime free.
    let (code, returned_state) = tokio::task::spawn_blocking(move || wait_for_code(listener))
        .await
        .map_err(|e| e.to_string())??;
    if returned_state != state {
        return Err("oauth state mismatch — possible CSRF; aborting".into());
    }

    let client = reqwest::Client::new();
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect.as_str()),
        ("client_id", client_id.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    let resp = client
        .post(token_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("token request: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("token endpoint {status}: {body}"));
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("token json: {e}: {body}"))?;
    let access = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| format!("no access_token in response: {body}"))?;
    let refresh = v
        .get("refresh_token")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string());
    let expires_in = v.get("expires_in").and_then(|e| e.as_u64());
    let scope = v
        .get("scope")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    set_access_token_full(
        paths,
        server,
        access,
        refresh,
        expires_in,
        scope,
        Some(token_url.to_string()),
        Some(client_id),
    )?;
    Ok(format!(
        "stored OAuth token for `{server}` in {} (refresh enabled)",
        credentials_path(paths).display()
    ))
}

fn wait_for_code(listener: TcpListener) -> Result<(String, String), String> {
    let (mut stream, _) = listener
        .accept()
        .map_err(|e| format!("accept callback: {e}"))?;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let first = req.lines().next().unwrap_or("");
    // GET /callback?code=…&state=… HTTP/1.1
    let path = first.split_whitespace().nth(1).unwrap_or("");
    let q = path.split('?').nth(1).unwrap_or("");
    let mut code = None;
    let mut state = None;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "code" => code = Some(urlencoding_decode(v)),
                "state" => state = Some(urlencoding_decode(v)),
                _ => {}
            }
        }
    }
    let body = "<html><body><h2>oscar MCP auth complete</h2><p>You can close this tab.</p></body></html>";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
    let code = code.ok_or_else(|| "callback missing code".to_string())?;
    let state = state.ok_or_else(|| "callback missing state".to_string())?;
    Ok((code, state))
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn urlencoding_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(h) = h {
                if let Ok(v) = u8::from_str_radix(h, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Status line for doctor / list (never includes token value).
pub fn token_status(paths: &Paths, server: &str) -> String {
    let file = load_credentials(paths);
    match file.servers.get(server) {
        None => "oauth=none".into(),
        Some(r) => {
            let exp = match r.expires_at {
                Some(e) if e <= now_unix() => "expired",
                Some(_) => "valid",
                None => "present",
            };
            format!("oauth={exp}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn credentials_roundtrip() {
        let tmp = tempdir().unwrap();
        let paths = Paths {
            config_dir: tmp.path().to_path_buf(),
            config_file: tmp.path().join("config.toml"),
            profiles_file: tmp.path().join("profiles.toml"),
            sessions_dir: tmp.path().join("sessions"),
            artifacts_dir: tmp.path().join("artifacts"),
            logs_dir: tmp.path().join("logs"),
            mcp_credentials_file: tmp.path().join("mcp_credentials.json"),
            auth_file: tmp.path().join("auth.json"),
        };
        set_access_token(&paths, "linear", "tok-abc", None, Some(3600), None).unwrap();
        assert_eq!(get_access_token(&paths, "linear").as_deref(), Some("tok-abc"));
        assert!(clear_token(&paths, "linear").unwrap());
        assert!(get_access_token(&paths, "linear").is_none());
    }

    #[test]
    fn pkce_challenge_stable_shape() {
        let c = pkce_challenge("test-verifier-0123456789");
        assert!(c.len() >= 40);
        assert!(!c.contains('='));
        assert!(!c.contains('+'));
        assert!(!c.contains('/'));
    }

    #[test]
    fn apply_token_skips_existing_auth_header() {
        let tmp = tempdir().unwrap();
        let paths = Paths {
            config_dir: tmp.path().to_path_buf(),
            config_file: tmp.path().join("c.toml"),
            profiles_file: tmp.path().join("p.toml"),
            sessions_dir: tmp.path().join("s"),
            artifacts_dir: tmp.path().join("a"),
            logs_dir: tmp.path().join("l"),
            mcp_credentials_file: tmp.path().join("mcp_credentials.json"),
        };
        set_access_token(&paths, "s", "secret", None, None, None).unwrap();
        let mut cfg = McpServerConfig::default();
        cfg.headers
            .insert("Authorization".into(), "Bearer manual".into());
        apply_stored_token(&paths, "s", &mut cfg);
        assert_eq!(cfg.headers.get("Authorization").unwrap(), "Bearer manual");
        let mut cfg2 = McpServerConfig::default();
        apply_stored_token(&paths, "s", &mut cfg2);
        assert_eq!(
            cfg2.headers.get("Authorization").unwrap(),
            "Bearer secret"
        );
    }
}
