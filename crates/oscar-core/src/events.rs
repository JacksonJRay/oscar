use crate::messages::TokenUsage;
use crate::types::AuthRequest;
use serde::{Deserialize, Serialize};

/// Snapshot of model context usage for the status meter and headless events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextSnapshot {
    pub model: String,
    pub context_window: u32,
    pub used_tokens: u32,
    pub reserved_output: u32,
    pub percent: f32,
    pub message_count: u32,
    pub compacted: bool,
    #[serde(default)]
    pub estimated: bool,
}

impl ContextSnapshot {
    pub fn compute(
        model: impl Into<String>,
        context_window: u32,
        used_tokens: u32,
        reserved_output: u32,
        message_count: u32,
        compacted: bool,
        estimated: bool,
    ) -> Self {
        // Display percent vs full model window (current / max) — matches Grok Build session-info style.
        let max = context_window.max(1);
        let percent = (used_tokens as f32 / max as f32) * 100.0;
        Self {
            model: model.into(),
            context_window,
            used_tokens,
            reserved_output,
            percent,
            message_count,
            compacted,
            estimated,
        }
    }

    /// Short status-bar form: `12.3k / 131k (9%)` with optional `~` when estimated.
    pub fn format_short(&self) -> String {
        let est = if self.estimated { "~" } else { "" };
        format!(
            "{est}{} / {} ({:.0}%)",
            format_token_count(self.used_tokens),
            format_token_count(self.context_window),
            self.percent.min(999.0)
        )
    }

    /// Explicit labels for status / slash: current, max, percent.
    pub fn format_labeled(&self) -> String {
        let est = if self.estimated { " (estimated)" } else { "" };
        format!(
            "context current={}  max={}  used={:.1}%{est}",
            self.used_tokens,
            self.context_window,
            self.percent.min(999.0)
        )
    }

    /// Multi-line detail for `/context` (Grok Build–style session usage).
    pub fn format_detail(&self, auto_threshold: f32) -> String {
        let free = self.context_window.saturating_sub(self.used_tokens);
        let usable = self
            .context_window
            .saturating_sub(self.reserved_output)
            .max(1);
        let usable_pct = (self.used_tokens as f32 / usable as f32) * 100.0;
        let thr = (auto_threshold * 100.0).round() as u32;
        let est = if self.estimated {
            "yes (char heuristic until provider usage)"
        } else {
            "no (from provider usage and/or estimate)"
        };
        format!(
            r#"# context window
model:            {}
current (used):   {} tokens
max (window):     {} tokens
used:             {:.1}%
free:             {} tokens
reserved output:  {} tokens
usable budget:    {} tokens ({:.1}% filled of usable)
messages:         {}
compacted:        {}
estimated:        {}
auto-compact at:  {}% of full context_window (Grok Build default 85)

Status line shows: current / max (percent%)
Soft-fold (tool head+tail trim) starts ~soft_threshold_tokens before that.
"#,
            self.model,
            self.used_tokens,
            self.context_window,
            self.percent.min(999.0),
            free,
            self.reserved_output,
            usable,
            usable_pct.min(999.0),
            self.message_count,
            self.compacted,
            est,
            thr,
        )
    }
}

/// Human-readable token counts for the status bar (e.g. 131072 → `131k`, 1536 → `1.5k`).
pub fn format_token_count(n: u32) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f32 / 1_000_000.0)
    } else if n >= 10_000 {
        format!("{}k", (n + 500) / 1000)
    } else if n >= 1000 {
        format!("{:.1}k", n as f32 / 1000.0)
    } else {
        n.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_shows_current_max_percent() {
        let s = ContextSnapshot::compute("m", 131_072, 13_107, 4096, 10, false, false);
        let short = s.format_short();
        assert!(short.contains('/'), "{short}");
        assert!(short.contains('%'), "{short}");
        assert!(s.format_labeled().contains("current="));
        assert!(s.format_labeled().contains("max="));
        assert!(s.format_labeled().contains("used="));
        // ~10% of full window
        assert!((s.percent - 10.0).abs() < 0.5);
        assert_eq!(format_token_count(131_072), "131k");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactReason {
    Threshold,
    Manual,
    PreFlight,
    ModelSwitch,
}

/// Unified agent → UI / headless event stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentEvent {
    ContentDelta { text: String },
    ThinkingDelta { text: String },
    ThinkingDone { chars: usize },

    ToolSearch { query: String, hits: usize },
    ToolStart {
        tool_id: String,
        args_redacted: serde_json::Value,
    },
    ToolEnd { tool_id: String, summary: String },

    ContextUsage(ContextSnapshot),
    CompactionStarted { reason: CompactReason },
    CompactionFinished {
        before: ContextSnapshot,
        after: ContextSnapshot,
    },

    /// Credentials needed; UI should collect secrets or show hint_commands.
    AuthRequired(AuthRequest),
    /// Tool execution paused pending auth; host should retry after credentials land.
    AuthPendingRetry {
        tool_id: String,
        tool_call_id: String,
        args: serde_json::Value,
        auth: AuthRequest,
    },
    /// Credentials accepted; agent is retrying the failed tool.
    AuthResumed {
        tool_id: String,
        profile_id: Option<String>,
    },
    /// Agent requests elevated package install; user must approve (admin priv).
    InstallApprovalRequired {
        packages: Vec<String>,
        commands: Vec<String>,
        reason: String,
        /// When true, user enabled install-all policy intent.
        install_all: bool,
    },
    InstallCompleted {
        ok: bool,
        summary: String,
    },
    ModeDenied { tool_id: String, reason: String },
    Error { message: String },
    Done { usage: Option<TokenUsage> },
}
