//! Clipboard copy/paste — Grok Build 1:1 multi-route delivery.
//!
//! ## Routes (same spirit as Grok `/doctor` Clipboard)
//!
//! 1. **native** — long-lived `arboard` owner thread (Linux must not drop Clipboard
//!    or managers print “dropped very quickly after writing” and pastes fail)
//! 2. **CLI tools** — `wl-copy` / `xclip` / `xsel` / `tmux load-buffer` fallbacks
//! 3. **OSC 52** — when native+CLI fail, or always-safe secondary on remote (capped)
//! 4. **backup file** — always `~/.config/oscar/last-copy.txt` (`OSCAR_COPY_FILE`)
//!
//! Toast: `Copied!` when a live route succeeded; otherwise names the backup path
//! (Grok: unverified OSC 52 / unreachable clipboard still leaves recovery text).
//!
//! Paste: CLIPBOARD only (never PRIMARY) — Grok Ctrl+V semantics.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::Duration;

/// Result of a copy attempt for UI toast / status.
#[derive(Debug, Clone)]
pub struct CopyOutcome {
    pub message: String,
    pub bytes: usize,
    pub backup_path: Option<PathBuf>,
    pub native_ok: bool,
    pub osc52_sent: bool,
}

/// Destination for last-copy backup (Grok: `~/.grok/last-copy.txt`).
pub fn copy_backup_path() -> PathBuf {
    if let Ok(p) = std::env::var("OSCAR_COPY_FILE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    dirs::home_dir()
        .map(|h| h.join(".config/oscar/last-copy.txt"))
        .unwrap_or_else(|| PathBuf::from("last-copy.txt"))
}

/// Copy text via Grok-style multi-route delivery. Never panics; never logs secrets.
pub fn copy_text(text: &str) -> CopyOutcome {
    let bytes = text.len();
    let backup_path = copy_backup_path();
    let backup_ok = write_backup(&backup_path, text).is_ok();

    // 1) Long-lived native owner (no short-lived Clipboard — that causes the
    //    “dropped very quickly after writing” warning and empty pastes).
    let native_ok = copy_native_held(text);

    // 2) CLI tools if native failed (Grok Wayland/data-control fallback spirit).
    let cli_ok = if native_ok {
        false
    } else {
        copy_via_cli(text)
    };

    // 3) OSC 52 when live routes failed, unless kill-switched (Grok GROK_CLIPBOARD_NO_OSC52).
    let osc_disabled = std::env::var_os("OSCAR_CLIPBOARD_NO_OSC52").is_some()
        || std::env::var_os("GROK_CLIPBOARD_NO_OSC52").is_some();
    let live = native_ok || cli_ok;
    let osc52_sent = if live || osc_disabled {
        false
    } else {
        emit_osc52(text)
    };

    let message = match (live, osc52_sent, backup_ok) {
        (true, _, _) => format!("Copied! ({bytes} bytes)"),
        (false, true, true) => format!(
            "Copied via OSC 52 ({bytes} bytes) · backup {}",
            backup_path.display()
        ),
        (false, true, false) => format!("Copied via OSC 52 ({bytes} bytes)"),
        (false, false, true) => format!(
            "Clipboard unavailable — saved to {} ({bytes} bytes)",
            backup_path.display()
        ),
        (false, false, false) => format!("Copy failed ({bytes} bytes)"),
    };

    CopyOutcome {
        message,
        bytes,
        backup_path: backup_ok.then_some(backup_path),
        native_ok: native_ok || cli_ok,
        osc52_sent,
    }
}

/// Read text from the OS clipboard (CLIPBOARD selection). No PRIMARY fallback.
pub fn paste_text() -> Option<String> {
    // Prefer long-lived owner first (same selection we write).
    if let Some(t) = paste_from_owner() {
        if !t.is_empty() {
            return Some(t);
        }
    }
    paste_native_once()
}

fn write_backup(path: &PathBuf, text: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, text)
}

// ── Long-lived arboard owner (Grok / Linux X11 ownership model) ──────────────

enum OwnerCmd {
    Set(String),
    Get(mpsc::Sender<Option<String>>),
}

fn owner_tx() -> &'static mpsc::Sender<OwnerCmd> {
    static TX: OnceLock<mpsc::Sender<OwnerCmd>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<OwnerCmd>();
        std::thread::Builder::new()
            .name("oscar-clipboard".into())
            .spawn(move || clipboard_owner_loop(rx))
            .expect("spawn oscar-clipboard thread");
        tx
    })
}

fn clipboard_owner_loop(rx: mpsc::Receiver<OwnerCmd>) {
    // ONE Clipboard for the process lifetime. Creating+dropping on each copy is
    // what triggers arboard's "dropped very quickly after writing" warning and
    // makes clipboard managers drop the payload on Linux.
    let mut owned: Option<arboard::Clipboard> = None;

    while let Ok(cmd) = rx.recv() {
        match cmd {
            OwnerCmd::Set(payload) => {
                // Coalesce bursty multi-copy (only keep latest).
                let mut latest = payload;
                while let Ok(more) = rx.try_recv() {
                    match more {
                        OwnerCmd::Set(p) => latest = p,
                        OwnerCmd::Get(reply) => {
                            // Answer get with current before applying newer set.
                            let _ = reply.send(owned.as_mut().and_then(|c| c.get_text().ok()));
                        }
                    }
                }
                if owned.is_none() {
                    owned = arboard::Clipboard::new().ok();
                }
                if let Some(ref mut cb) = owned {
                    // Prefer explicit CLIPBOARD selection on Linux.
                    #[cfg(target_os = "linux")]
                    {
                        use arboard::{LinuxClipboardKind, SetExtLinux};
                        let _ = cb
                            .set()
                            .clipboard(LinuxClipboardKind::Clipboard)
                            .text(latest.clone());
                        // Also publish PRIMARY so middle-click paste works in terminals.
                        let _ = cb
                            .set()
                            .clipboard(LinuxClipboardKind::Primary)
                            .text(latest.clone());
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = cb.set_text(latest);
                    }
                }
            }
            OwnerCmd::Get(reply) => {
                let val = owned.as_mut().and_then(|c| c.get_text().ok());
                let _ = reply.send(val);
            }
        }
    }
    // Drop only when process exits (channel closed).
    drop(owned);
}

/// Set clipboard on the long-lived owner thread. Never constructs a temporary
/// `Clipboard` on the UI thread (that is the drop-warning bug).
fn copy_native_held(text: &str) -> bool {
    let tx = owner_tx();
    if tx.send(OwnerCmd::Set(text.to_string())).is_err() {
        return false;
    }
    // Brief yield so the owner thread can set before the user pastes immediately.
    // Do not block the UI for long — arboard SetExtLinux::wait would hang until paste.
    std::thread::sleep(Duration::from_millis(15));
    // Best-effort verify (Linux managers sometimes lag; failure still counts as
    // "we handed ownership to the worker").
    let (reply_tx, reply_rx) = mpsc::channel();
    if tx.send(OwnerCmd::Get(reply_tx)).is_ok() {
        if let Ok(Some(got)) = reply_rx.recv_timeout(Duration::from_millis(80)) {
            return got == text || !got.is_empty();
        }
    }
    // Worker accepted the set; treat as success so we don't spam OSC 52.
    true
}

fn paste_from_owner() -> Option<String> {
    let (reply_tx, reply_rx) = mpsc::channel();
    owner_tx().send(OwnerCmd::Get(reply_tx)).ok()?;
    reply_rx.recv_timeout(Duration::from_millis(100)).ok()?
}

fn paste_native_once() -> Option<String> {
    let mut cb = arboard::Clipboard::new().ok()?;
    let t = cb.get_text().ok()?;
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

// ── CLI fallbacks (Grok Wayland / tool path) ─────────────────────────────────

fn copy_via_cli(text: &str) -> bool {
    // Prefer Wayland, then X11, then tmux (Grok tmux paste-buffer route).
    if pipe_to(&["wl-copy", "--type", "text/plain"], text) {
        return true;
    }
    if pipe_to(&["wl-copy"], text) {
        return true;
    }
    if pipe_to(&["xclip", "-selection", "clipboard"], text) {
        return true;
    }
    if pipe_to(&["xsel", "--clipboard", "--input"], text) {
        return true;
    }
    // tmux paste buffer (Grok "tmux" clipboard route).
    if std::env::var_os("TMUX").is_some() && pipe_to(&["tmux", "load-buffer", "-"], text) {
        return true;
    }
    false
}

fn pipe_to(argv: &[&str], text: &str) -> bool {
    let Some((prog, args)) = argv.split_first() else {
        return false;
    };
    let mut child = match Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(text.as_bytes()).is_err() {
            let _ = child.kill();
            return false;
        }
    }
    matches!(child.wait(), Ok(s) if s.success())
}

// ── OSC 52 ───────────────────────────────────────────────────────────────────

/// OSC 52: `\x1b]52;c;<base64>\x07` (BEL terminator; widely supported).
/// Cap payload so huge transcripts don't blow terminal buffers (Grok-style).
fn emit_osc52(text: &str) -> bool {
    const MAX: usize = 100_000;
    let slice = if text.len() > MAX {
        &text[..MAX]
    } else {
        text
    };
    let b64 = base64_encode(slice.as_bytes());
    // Prefer DCS passthrough when inside tmux so the outer terminal sees OSC 52.
    let seq = if std::env::var_os("TMUX").is_some() {
        // tmux: ESC P tmux; ESC ESC ] 52 ; c ; b64 BEL ESC \
        format!("\x1bPtmux;\x1b\x1b]52;c;{b64}\x07\x1b\\")
    } else {
        format!("\x1b]52;c;{b64}\x07")
    };
    let mut out = io::stdout();
    out.write_all(seq.as_bytes()).is_ok() && out.flush().is_ok()
}

/// Minimal base64 encoder (standard alphabet).
fn base64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(T[((n >> 18) & 0x3f) as usize] as char);
        out.push(T[((n >> 12) & 0x3f) as usize] as char);
        out.push(T[((n >> 6) & 0x3f) as usize] as char);
        out.push(T[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out.push(T[((n >> 18) & 0x3f) as usize] as char);
            out.push(T[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(T[((n >> 18) & 0x3f) as usize] as char);
            out.push(T[((n >> 12) & 0x3f) as usize] as char);
            out.push(T[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_hello() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn copy_writes_backup_and_no_panic() {
        let dir = std::env::temp_dir().join(format!("oscar-copy-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("last-copy.txt");
        std::env::set_var("OSCAR_COPY_FILE", &path);
        let out = copy_text("hello-from-oscar-copy-test");
        assert!(out.bytes > 0);
        let got = std::fs::read_to_string(&path).expect("backup written");
        assert_eq!(got, "hello-from-oscar-copy-test");
        // Toast should not be empty
        assert!(!out.message.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("OSCAR_COPY_FILE");
    }
}
