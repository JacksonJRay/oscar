//! Clipboard copy/paste with Grok Build–style multi-route delivery.
//!
//! Routes (best-effort, in order):
//! 1. Native OS clipboard (`arboard`) when available
//! 2. OSC 52 escape sequence (SSH/tmux/remote-friendly)
//! 3. Always write a backup file (`~/.config/oscar/last-copy.txt` or `OSCAR_COPY_FILE`)
//!
//! Paste prefers native clipboard, then returns `None` (terminal Shift+Insert still works).

use std::io::{self, Write};
use std::path::PathBuf;

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

/// Copy text to clipboard + backup. Never panics.
pub fn copy_text(text: &str) -> CopyOutcome {
    let bytes = text.len();
    let backup_path = copy_backup_path();
    let backup_ok = write_backup(&backup_path, text).is_ok();

    let native_ok = copy_native(text);
    let osc52_sent = emit_osc52(text);

    let message = match (native_ok, osc52_sent, backup_ok) {
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
        native_ok,
        osc52_sent,
    }
}

/// Read text from the OS clipboard (CLIPBOARD selection). No PRIMARY fallback.
pub fn paste_text() -> Option<String> {
    paste_native()
}

fn write_backup(path: &PathBuf, text: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, text)
}

fn copy_native(text: &str) -> bool {
    match arboard::Clipboard::new() {
        Ok(mut cb) => cb.set_text(text.to_string()).is_ok(),
        Err(_) => false,
    }
}

fn paste_native() -> Option<String> {
    let mut cb = arboard::Clipboard::new().ok()?;
    let t = cb.get_text().ok()?;
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

/// OSC 52: `\x1b]52;c;<base64>\x07` (BEL terminator; widely supported).
fn emit_osc52(text: &str) -> bool {
    // Cap payload so huge transcripts don't blow terminal buffers (Grok-style caution).
    const MAX: usize = 100_000;
    let slice = if text.len() > MAX {
        &text[..MAX]
    } else {
        text
    };
    let b64 = base64_encode(slice.as_bytes());
    let seq = format!("\x1b]52;c;{b64}\x07");
    let mut out = io::stdout();
    // Best-effort; ignore errors (e.g. no TTY).
    let ok = out.write_all(seq.as_bytes()).is_ok() && out.flush().is_ok();
    ok
}

/// Minimal base64 encoder (standard alphabet, no padding dependency).
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
}
