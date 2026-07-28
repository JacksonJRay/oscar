//! Grok / xAI OAuth (SpaceXAI at `auth.x.ai`).
//!
//! Two interactive flows (same as Grok Build CLI):
//! 1. **Browser PKCE** (default) — loopback `http://127.0.0.1:<port>/callback`
//! 2. **Device code** — headless / SSH (`oscar auth login --device`)
//!
//! Tokens live in the unified AuthStore (`~/.config/oscar/auth.json`, mode 0600)
//! as `type: oauth` for provider `xai`. Access tokens are dual-written to the OS
//! keychain under `oscar/provider/xai`. Secrets never enter the chat transcript.
//!
//! Public OIDC client id is the Grok Build CLI public client (embedded in the
//! official binary; no client secret — PKCE only).

use crate::auth_store::{self, AuthEntry};
use oscar_core::Paths;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// SpaceXAI / xAI OIDC issuer (Grok Build default).
pub const XAI_ISSUER: &str = "https://auth.x.ai";
pub const XAI_AUTHORIZE_URL: &str = "https://auth.x.ai/oauth2/authorize";
pub const XAI_TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";
pub const XAI_DEVICE_CODE_URL: &str = "https://auth.x.ai/oauth2/device/code";
pub const XAI_API_BASE: &str = "https://api.x.ai/v1";

/// Public OIDC client id used by the official Grok Build CLI (PKCE public client).
pub const XAI_PUBLIC_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";

/// Scopes for CLI/agent access + silent refresh.
///
/// Do **not** include `team:read` / `org:read` — xAI rejects them for User
/// principals (`invalid_scope` / "not valid for User principals"), which broke
/// SuperGrok device + browser login entirely.
pub const XAI_SCOPES: &str =
    "openid profile email offline_access api:access grok-cli:access";

/// Provider ids that share the same Grok/xAI OAuth slot.
pub fn is_xai_family(id: &str) -> bool {
    matches!(
        id,
        "xai" | "grok" | "x-ai" | "xai-oauth" | "grok-oauth" | "xai-grok-oauth"
    )
}

/// Canonical keychain / auth.json slot for Grok credentials.
pub fn xai_canonical_id() -> &'static str {
    "xai"
}

// ── Session type (login UX + refresh) ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthSession {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Unix expiry of access_token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub client_id: String,
    pub issuer: String,
    #[serde(default)]
    pub updated_at: u64,
    /// How the session was obtained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn session_from_entry(e: &AuthEntry) -> Option<OAuthSession> {
    match e {
        AuthEntry::Oauth {
            access,
            refresh,
            expires,
            account_id,
            email,
            client_id,
            issuer,
            scope,
            id_token,
            token_type,
            auth_mode,
            updated_at,
            ..
        } => Some(OAuthSession {
            access_token: access.clone(),
            refresh_token: refresh.clone(),
            id_token: id_token.clone(),
            token_type: token_type.clone(),
            expires_at: *expires,
            scope: scope.clone(),
            email: email.clone(),
            user_id: account_id.clone(),
            client_id: client_id.clone().unwrap_or_else(|| XAI_PUBLIC_CLIENT_ID.into()),
            issuer: issuer.clone().unwrap_or_else(|| XAI_ISSUER.into()),
            updated_at: updated_at.unwrap_or(0),
            auth_mode: auth_mode.clone(),
        }),
        _ => None,
    }
}

fn entry_from_session(s: &OAuthSession) -> AuthEntry {
    AuthEntry::Oauth {
        access: s.access_token.clone(),
        refresh: s.refresh_token.clone(),
        expires: s.expires_at,
        account_id: s.user_id.clone(),
        email: s.email.clone(),
        client_id: Some(s.client_id.clone()),
        issuer: Some(s.issuer.clone()),
        scope: s.scope.clone(),
        id_token: s.id_token.clone(),
        token_type: s.token_type.clone(),
        auth_mode: s.auth_mode.clone(),
        updated_at: Some(s.updated_at),
        metadata: BTreeMap::new(),
    }
}

pub fn clear_xai_oauth(paths: &Paths) -> Result<(), String> {
    auth_store::remove(paths, xai_canonical_id())
}

pub fn oauth_status(paths: &Paths) -> Option<OAuthSession> {
    auth_store::get(paths, xai_canonical_id()).and_then(|e| session_from_entry(&e))
}

// ── Token use / refresh ──────────────────────────────────────────────────────

/// Valid bearer token for Grok/xAI **OAuth / SuperGrok** calls, refreshing if near expiry.
///
/// Returns `Ok(None)` only when no OAuth entry exists (caller may use API key for payg).
/// If an OAuth entry exists but is unusable, returns `Err` so we never silently use API key.
pub async fn get_valid_xai_access_token(paths: &Paths) -> Result<Option<String>, String> {
    let Some(mut rec) = oauth_status(paths) else {
        return Ok(None);
    };
    let expired = rec
        .expires_at
        .map(|e| now_unix() >= e)
        .unwrap_or(false);
    let needs_refresh = rec
        .expires_at
        .map(|e| now_unix() + 120 >= e)
        .unwrap_or(true); // unknown expiry → try refresh if we have a refresh token
    if needs_refresh {
        if let Some(rt) = rec.refresh_token.clone() {
            match refresh_token(paths, &rt, &rec.client_id).await {
                Ok(updated) => {
                    rec = updated;
                }
                Err(e) => {
                    warn!(error = %e, "xAI OAuth refresh failed");
                    if expired {
                        return Err(format!(
                            "SuperGrok OAuth expired and refresh failed: {e}. \
                             Sign in again (Google/SuperGrok): oscar auth login  or  oscar auth login --device \
                             — do not use API key for subscription models"
                        ));
                    }
                    // Not fully expired yet: try existing access once.
                }
            }
        } else if expired {
            return Err(
                "SuperGrok OAuth expired (no refresh token). Run: oscar auth login --device".into(),
            );
        }
    }
    if rec.access_token.is_empty() {
        return Err(
            "SuperGrok OAuth entry has empty access token. Run: oscar auth login".into(),
        );
    }
    Ok(Some(rec.access_token))
}

async fn refresh_token(
    paths: &Paths,
    refresh: &str,
    client_id: &str,
) -> Result<OAuthSession, String> {
    let client = reqwest::Client::new();
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh),
        ("client_id", client_id),
    ];
    let resp = client
        .post(XAI_TOKEN_URL)
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("refresh request: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("refresh {status}: {body}"));
    }
    let session = parse_token_response(&body, client_id, "refresh")?;
    store_session(paths, session.clone())?;
    info!("refreshed Grok/xAI OAuth access token");
    Ok(session)
}

fn store_session(paths: &Paths, session: OAuthSession) -> Result<(), String> {
    // AuthStore dual-writes to keychain under oscar/provider/xai (+ grok alias).
    auth_store::set(paths, xai_canonical_id(), entry_from_session(&session))
}

fn parse_token_response(
    body: &str,
    client_id: &str,
    mode: &str,
) -> Result<OAuthSession, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("token json: {e}: {body}"))?;
    let access = v
        .get("access_token")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("no access_token in response: {body}"))?
        .to_string();
    let refresh = v
        .get("refresh_token")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let id_token = v
        .get("id_token")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let token_type = v
        .get("token_type")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let scope = v
        .get("scope")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let expires_in = v
        .get("expires_in")
        .and_then(|x| x.as_u64())
        .unwrap_or(3600);
    let expires_at = Some(now_unix().saturating_add(expires_in));

    // Best-effort user claims from id_token payload (no signature verify here —
    // token is used as bearer against api.x.ai which validates server-side).
    let (email, user_id) = id_token
        .as_deref()
        .and_then(peek_jwt_claims)
        .unwrap_or((None, None));

    Ok(OAuthSession {
        access_token: access,
        refresh_token: refresh,
        id_token,
        token_type,
        expires_at,
        scope,
        email,
        user_id,
        client_id: client_id.into(),
        issuer: XAI_ISSUER.into(),
        updated_at: now_unix(),
        auth_mode: Some(mode.into()),
    })
}

fn peek_jwt_claims(jwt: &str) -> Option<(Option<String>, Option<String>)> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let payload = b64url_decode(parts[1])?;
    let v: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let email = v.get("email").and_then(|e| e.as_str()).map(str::to_string);
    let sub = v.get("sub").and_then(|e| e.as_str()).map(str::to_string);
    Some((email, sub))
}

// ── Browser PKCE login ───────────────────────────────────────────────────────

/// Interactive browser OAuth (authorization code + PKCE). Opens the system browser.
pub async fn run_browser_login(paths: &Paths) -> Result<OAuthSession, String> {
    let client_id = XAI_PUBLIC_CLIENT_ID.to_string();
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind callback: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let verifier = random_urlsafe(32);
    let challenge = pkce_challenge(&verifier);
    let state = random_urlsafe(16);

    let auth = format!(
        "{XAI_AUTHORIZE_URL}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}&scope={}",
        urlencoding_encode(&client_id),
        urlencoding_encode(&redirect),
        urlencoding_encode(&challenge),
        urlencoding_encode(&state),
        urlencoding_encode(XAI_SCOPES),
    );

    println!("Grok / xAI OAuth (browser PKCE)");
    println!("Open this URL if the browser does not open:\n  {auth}\n");
    if let Err(e) = open_browser(&auth) {
        eprintln!("note: {e}");
    }
    println!("Waiting for browser callback on {redirect} …");

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
        .post(XAI_TOKEN_URL)
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("token request: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("token endpoint {status}: {body}"));
    }
    let session = parse_token_response(&body, &client_id, "browser")?;
    store_session(paths, session.clone())?;
    print_login_ok(&session);
    Ok(session)
}

// ── Device code login ────────────────────────────────────────────────────────

/// Headless / SSH-friendly device authorization grant.
pub async fn run_device_login(paths: &Paths) -> Result<OAuthSession, String> {
    let client_id = XAI_PUBLIC_CLIENT_ID.to_string();
    let http = reqwest::Client::new();
    let form = [
        ("client_id", client_id.as_str()),
        ("scope", XAI_SCOPES),
    ];
    let resp = http
        .post(XAI_DEVICE_CODE_URL)
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("device code request: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("device code {status}: {body}"));
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("device json: {e}: {body}"))?;
    let device_code = v
        .get("device_code")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("no device_code: {body}"))?
        .to_string();
    let user_code = v
        .get("user_code")
        .and_then(|x| x.as_str())
        .unwrap_or("?")
        .to_string();
    let verification_uri = v
        .get("verification_uri_complete")
        .and_then(|x| x.as_str())
        .or_else(|| v.get("verification_uri").and_then(|x| x.as_str()))
        // xAI device portal (not the generic sign-in page).
        .unwrap_or("https://accounts.x.ai/oauth2/device")
        .to_string();
    let interval = v
        .get("interval")
        .and_then(|x| x.as_u64())
        .unwrap_or(5)
        .max(2);
    let expires_in = v
        .get("expires_in")
        .and_then(|x| x.as_u64())
        .unwrap_or(600);

    println!("Grok / xAI OAuth (device code — headless friendly)");
    println!("1. Open: {verification_uri}");
    println!("2. Enter code: {user_code}");
    println!("   (or open the complete URL if it already includes the code)\n");
    let _ = open_browser(&verification_uri);
    println!("Waiting for approval (expires in ~{expires_in}s) …");

    let deadline = now_unix() + expires_in;
    loop {
        if now_unix() >= deadline {
            return Err("device code expired — run: oscar auth login --device".into());
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let form = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code.as_str()),
            ("client_id", client_id.as_str()),
        ];
        let resp = http
            .post(XAI_TOKEN_URL)
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("token poll: {e}"))?;
        let status = resp.status();
        let body = resp.text().await.map_err(|e| e.to_string())?;
        if status.is_success() {
            let session = parse_token_response(&body, &client_id, "device")?;
            store_session(paths, session.clone())?;
            print_login_ok(&session);
            return Ok(session);
        }
        // RFC 8628 pending states
        if let Ok(err) = serde_json::from_str::<serde_json::Value>(&body) {
            let e = err.get("error").and_then(|x| x.as_str()).unwrap_or("");
            match e {
                "authorization_pending" | "slow_down" => {
                    if e == "slow_down" {
                        tokio::time::sleep(Duration::from_secs(interval)).await;
                    }
                    continue;
                }
                "access_denied" => {
                    return Err("authorization denied by user".into());
                }
                "expired_token" => {
                    return Err("device code expired — run: oscar auth login --device".into());
                }
                _ => {
                    return Err(format!("device token error {status}: {body}"));
                }
            }
        }
        return Err(format!("device token error {status}: {body}"));
    }
}

fn print_login_ok(session: &OAuthSession) {
    let who = session
        .email
        .clone()
        .or_else(|| session.user_id.clone())
        .unwrap_or_else(|| "signed in".into());
    let mode = session.auth_mode.as_deref().unwrap_or("oauth");
    println!("✓ Grok SuperGrok OAuth ready — {who} (mode={mode})");
    println!("  Tokens: ~/.config/oscar/auth.json (0600) + OS keychain oscar/provider/xai");
    println!("  Auth type: oauth (subscription) — preferred over API key for Grok/xAI");
    println!("  Default: oscar provider set grok");
    println!("  Models:  oscar ask --provider grok --model grok-build-0.1 \"…\"");
    println!("  Logout:  oscar auth logout");
}

// ── Shared helpers ───────────────────────────────────────────────────────────

fn wait_for_code(listener: TcpListener) -> Result<(String, String), String> {
    let (mut stream, _) = listener
        .accept()
        .map_err(|e| format!("accept callback: {e}"))?;
    let mut buf = [0u8; 4096];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("read callback: {e}"))?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let line = req.lines().next().unwrap_or("");
    // GET /callback?code=...&state=... HTTP/1.1
    let path = line.split_whitespace().nth(1).unwrap_or("");
    let q = path.split('?').nth(1).unwrap_or("");
    let mut code = None;
    let mut state = None;
    for pair in q.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        let v = urlencoding_decode(v);
        match k {
            "code" => code = Some(v),
            "state" => state = Some(v),
            "error" => {
                let desc = q
                    .split('&')
                    .find(|p| p.starts_with("error_description="))
                    .map(|p| urlencoding_decode(p.trim_start_matches("error_description=")))
                    .unwrap_or_default();
                let _ = stream.write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n<html><body><h1>Login failed</h1><p>You can close this tab.</p></body></html>",
                );
                return Err(format!("oauth error: {v} {desc}"));
            }
            _ => {}
        }
    }
    let code = code.ok_or_else(|| "callback missing code".to_string())?;
    let state = state.ok_or_else(|| "callback missing state".to_string())?;
    let body = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n<html><body style=\"font-family:system-ui;padding:2rem\"><h1>oscar - Grok signed in</h1><p>You can close this tab and return to the terminal.</p></body></html>";
    let _ = stream.write_all(body);
    Ok((code, state))
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

fn random_urlsafe(n: usize) -> String {
    let mut buf = vec![0u8; n];
    if getrandom_fill(&mut buf).is_err() {
        let t = now_unix().to_le_bytes();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = t[i % t.len()].wrapping_add(i as u8).wrapping_mul(17);
        }
    }
    b64url_no_pad(&buf)
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), ()> {
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
    b64url_no_pad(&hasher.finalize())
}

fn b64url_no_pad(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
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

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut s = s.replace('-', "+").replace('_', "/");
    while s.len() % 4 != 0 {
        s.push('=');
    }
    // Minimal base64 decode without extra crate
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        let c = val(bytes[i + 2])?;
        let d = val(bytes[i + 3])?;
        out.push((a << 2) | (b >> 4));
        if bytes[i + 2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if bytes[i + 3] != b'=' {
            out.push((c << 6) | d);
        }
        i += 4;
    }
    Some(out)
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn urlencoding_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = || -> Option<u8> {
                let hi = (bytes[i + 1] as char).to_digit(16)? as u8;
                let lo = (bytes[i + 2] as char).to_digit(16)? as u8;
                Some((hi << 4) | lo)
            };
            if let Some(v) = h() {
                out.push(v);
                i += 3;
                continue;
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

/// Human-readable status line for CLI / TUI.
pub fn status_line(paths: &Paths) -> String {
    match oauth_status(paths) {
        Some(s) => {
            let who = s.email.as_deref().unwrap_or("signed in");
            let exp = s
                .expires_at
                .map(|e| {
                    if now_unix() + 120 >= e {
                        "expiring soon / refreshable".into()
                    } else {
                        let left = e.saturating_sub(now_unix());
                        format!("expires in {}m", left / 60)
                    }
                })
                .unwrap_or_else(|| "no expiry".into());
            let mode = s.auth_mode.as_deref().unwrap_or("oauth");
            format!("Grok OAuth: ready · {who} · {mode} · {exp}")
        }
        None => "Grok OAuth: not signed in — run `oscar auth login` (or --device)".into(),
    }
}

/// True if we have a non-empty OAuth or keychain credential for Grok/xAI.
pub fn xai_ready(paths: &Paths) -> bool {
    if crate::auth_store::has_credentials(paths, xai_canonical_id()) {
        return true;
    }
    matches!(
        oscar_identity::load_provider_api_key(xai_canonical_id()),
        Ok(Some(k)) if !k.is_empty()
    ) || matches!(
        oscar_identity::load_provider_api_key("grok"),
        Ok(Some(k)) if !k.is_empty()
    )
}

// silence unused import if any
#[allow(dead_code)]
fn _json_helper() {
    let _ = json!({});
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_ids() {
        assert!(is_xai_family("grok"));
        assert!(is_xai_family("xai"));
        assert!(!is_xai_family("openai"));
    }

    #[test]
    fn pkce_shape() {
        let c = pkce_challenge("test-verifier-value-with-enough-entropy");
        assert!(c.len() >= 40);
        assert!(!c.contains('+') && !c.contains('/'));
    }
}
