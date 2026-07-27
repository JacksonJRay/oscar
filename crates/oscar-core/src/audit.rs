//! Local tool-execution audit log (Phase 6).
//!
//! Appends one JSON line per tools_execute to `~/.config/oscar/logs/tool_audit.jsonl`.
//! Secrets must already be redacted by the caller.

use crate::Paths;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct ToolAuditEvent {
    pub ts: u64,
    pub tool_id: String,
    pub ok: bool,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Redacted args preview (short).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_preview: Option<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Best-effort append; never panics the agent.
pub fn append_tool_audit(event: ToolAuditEvent) {
    let Ok(paths) = Paths::discover() else {
        return;
    };
    if paths.ensure().is_err() {
        return;
    }
    let path = paths.logs_dir.join("tool_audit.jsonl");
    let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) else {
        return;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    if let Ok(line) = serde_json::to_string(&event) {
        let _ = writeln!(f, "{line}");
    }
}

pub fn audit_tool_execute(
    tool_id: &str,
    ok: bool,
    summary: &str,
    mode: Option<&str>,
    session_id: Option<&str>,
    args_preview: Option<&str>,
) {
    append_tool_audit(ToolAuditEvent {
        ts: now_unix(),
        tool_id: tool_id.to_string(),
        ok,
        summary: summary.chars().take(240).collect(),
        mode: mode.map(|s| s.to_string()),
        session_id: session_id.map(|s| s.to_string()),
        args_preview: args_preview.map(|s| s.chars().take(200).collect()),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serializes() {
        let e = ToolAuditEvent {
            ts: 1,
            tool_id: "aws.dns.pattern.search".into(),
            ok: true,
            summary: "ok".into(),
            mode: Some("readonly".into()),
            session_id: None,
            args_preview: Some(r#"{"pattern":"x"}"#.into()),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("aws.dns.pattern.search"));
    }
}
