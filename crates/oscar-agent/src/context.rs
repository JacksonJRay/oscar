//! Context window tracking and Grok Build–style auto-compaction.
//!
//! Parity notes (Grok Build / `~/.grok` docs):
//! - Auto-compact at **`auto_compact_threshold_percent` default 85%** of the
//!   model **context_window** (`[session] auto_compact_threshold_percent = 85`).
//! - User-visible notification when auto-compact fires.
//! - Manual `/compact [keep note]` with optional preserve instructions.
//! - Optional soft headroom before hard compact (tool-result folding only).
//! - Compaction checkpoints under the session store (best-effort).

use oscar_core::config::ContextSettings;
use oscar_core::events::{CompactReason, ContextSnapshot};
use oscar_core::{Message, MessageRole, TokenUsage};

/// Configuration for automatic and manual compaction.
#[derive(Debug, Clone)]
pub struct CompactConfig {
    /// Fraction of **full** context_window that triggers auto-compact (Grok: 0.85).
    pub threshold: f32,
    /// Reserved for model completion; used in usable-budget display, not the trip %.
    pub reserved_output_tokens: u32,
    /// Recent non-system messages to keep intact.
    pub keep_recent_turns: u32,
    pub keep_latest_thinking: bool,
    pub auto: bool,
    /// Soft headroom (tokens) before hard threshold — light tool fold only (Grok soft flush).
    pub soft_threshold_tokens: u32,
}

impl From<&ContextSettings> for CompactConfig {
    fn from(s: &ContextSettings) -> Self {
        Self {
            threshold: s.threshold,
            reserved_output_tokens: s.reserved_output_tokens,
            keep_recent_turns: s.keep_recent_turns,
            keep_latest_thinking: s.keep_latest_thinking,
            auto: s.auto,
            soft_threshold_tokens: s.soft_threshold_tokens,
        }
    }
}

impl Default for CompactConfig {
    fn default() -> Self {
        Self {
            // Grok Build default: auto_compact_threshold_percent = 85
            threshold: 0.85,
            reserved_output_tokens: 4096,
            keep_recent_turns: 6,
            keep_latest_thinking: true,
            auto: true,
            // Grok compaction.memory_flush soft_threshold_tokens default ≈ 4000
            soft_threshold_tokens: 4000,
        }
    }
}

/// Optional knobs for a single compact invocation.
#[derive(Debug, Clone)]
pub struct CompactRequest {
    pub reason: CompactReason,
    /// From `/compact keep the auth implementation details` (Grok preserve note).
    pub keep_note: Option<String>,
}

impl Default for CompactRequest {
    fn default() -> Self {
        Self {
            reason: CompactReason::Manual,
            keep_note: None,
        }
    }
}

/// Tracks token budget, estimates usage, and compacts session history.
pub struct ContextManager {
    pub model: String,
    pub context_window: u32,
    pub config: CompactConfig,
    pub last_usage: Option<TokenUsage>,
    pub estimated_tokens: u32,
    pub compacted: bool,
    /// Large tool payloads kept out of the model window.
    pub artifacts: std::collections::HashMap<String, serde_json::Value>,
    /// How many times compact has run this session.
    pub compact_count: u32,
}

impl ContextManager {
    pub fn new(model: impl Into<String>, context_window: u32, config: CompactConfig) -> Self {
        Self {
            model: model.into(),
            context_window,
            config,
            last_usage: None,
            estimated_tokens: 0,
            compacted: false,
            artifacts: std::collections::HashMap::new(),
            compact_count: 0,
        }
    }

    pub fn set_model(&mut self, model: impl Into<String>, context_window: u32) {
        self.model = model.into();
        self.context_window = context_window;
    }

    /// Rough token estimate: ~4 chars per token.
    pub fn estimate_messages(messages: &[Message]) -> u32 {
        let mut chars = 0usize;
        for m in messages {
            chars += m.content.len();
            if let Some(t) = &m.thinking {
                chars += t.len();
            }
            for tc in &m.tool_calls {
                chars += tc.name.len() + tc.arguments.to_string().len();
            }
        }
        (chars as u32 / 4).max(1)
    }

    pub fn observe_usage(&mut self, usage: TokenUsage) {
        let from_provider = usage.total_tokens.max(usage.input_tokens);
        self.estimated_tokens = self.estimated_tokens.max(from_provider);
        self.last_usage = Some(usage);
    }

    /// Refresh usage from the live message list (always re-estimates growing tool payloads).
    pub fn observe_messages(&mut self, messages: &[Message]) {
        let est = Self::estimate_messages(messages);
        let from_provider = self
            .last_usage
            .as_ref()
            .map(|u| u.total_tokens.max(u.input_tokens))
            .unwrap_or(0);
        self.estimated_tokens = est.max(from_provider);
    }

    pub fn used_tokens(&self) -> u32 {
        let from_provider = self
            .last_usage
            .as_ref()
            .map(|u| u.total_tokens.max(u.input_tokens))
            .unwrap_or(0);
        from_provider.max(self.estimated_tokens)
    }

    /// Fraction of **full context_window** filled (Grok Build trip metric).
    pub fn usage_ratio(&self) -> f32 {
        let max = self.context_window.max(1);
        self.used_tokens() as f32 / max as f32
    }

    /// Soft zone: within `soft_threshold_tokens` of the hard percent threshold.
    pub fn in_soft_zone(&self) -> bool {
        if !self.config.auto {
            return false;
        }
        let max = self.context_window.max(1) as f32;
        let hard = self.config.threshold * max;
        let soft_start = hard - self.config.soft_threshold_tokens as f32;
        let used = self.used_tokens() as f32;
        used >= soft_start && used < hard
    }

    pub fn snapshot(&self, message_count: u32) -> ContextSnapshot {
        let used = self.used_tokens();
        let estimated = self.last_usage.is_none()
            || self.estimated_tokens
                > self
                    .last_usage
                    .as_ref()
                    .map(|u| u.total_tokens.max(u.input_tokens))
                    .unwrap_or(0);
        ContextSnapshot::compute(
            &self.model,
            self.context_window,
            used,
            self.config.reserved_output_tokens,
            message_count,
            self.compacted,
            estimated,
        )
    }

    /// Hard auto-compact when usage ≥ threshold % of **full** context window (Grok: 85%).
    pub fn should_compact(&self) -> bool {
        if !self.config.auto {
            return false;
        }
        self.usage_ratio() >= self.config.threshold
    }

    /// Light fold only (tool dumps) when approaching threshold — Grok soft flush analogue.
    pub fn should_soft_fold(&self) -> bool {
        self.config.auto && self.in_soft_zone() && !self.should_compact()
    }

    /// Soft-fold: Grok-style tool-result pruning before hard compact.
    ///
    /// Mirrors `[compaction.pruning]`: soft-trim large older tool dumps with
    /// head+tail keep (`soft_trim_head`/`soft_trim_tail` analogue ≈ 1500 chars),
    /// never touching the most recent `keep_recent_turns` non-system messages.
    pub fn soft_fold_tools(&mut self, messages: &mut [Message]) -> usize {
        // Grok defaults: soft_trim_threshold=4000, soft_trim_head/tail=1500
        const SOFT_TRIM_THRESHOLD: usize = 4000;
        const SOFT_TRIM_HEAD: usize = 1500;
        const SOFT_TRIM_TAIL: usize = 1500;

        let mut n = 0usize;
        let keep = self.config.keep_recent_turns as usize;
        let non_sys: Vec<usize> = messages
            .iter()
            .enumerate()
            .filter(|(_, m)| m.role != MessageRole::System)
            .map(|(i, _)| i)
            .collect();
        let fold_before = non_sys.len().saturating_sub(keep);
        for (rank, &idx) in non_sys.iter().enumerate() {
            if rank >= fold_before {
                continue;
            }
            let m = &mut messages[idx];
            if m.role == MessageRole::Tool && m.content.len() > SOFT_TRIM_THRESHOLD {
                let chars: Vec<char> = m.content.chars().collect();
                let head: String = chars.iter().take(SOFT_TRIM_HEAD).collect();
                let tail: String = chars
                    .iter()
                    .rev()
                    .take(SOFT_TRIM_TAIL)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                m.content = format!(
                    "[soft-trimmed tool result — re-run tools if needed]\n{head}\n…\n{tail}"
                );
                n += 1;
            }
        }
        if n > 0 {
            self.observe_messages(messages);
        }
        n
    }

    pub fn compact(
        &mut self,
        messages: &mut Vec<Message>,
        reason: CompactReason,
    ) -> (ContextSnapshot, ContextSnapshot) {
        self.compact_with(messages, CompactRequest { reason, keep_note: None })
    }

    /// Full compact (Grok `/compact` / auto-compact).
    pub fn compact_with(
        &mut self,
        messages: &mut Vec<Message>,
        req: CompactRequest,
    ) -> (ContextSnapshot, ContextSnapshot) {
        self.observe_messages(messages);
        let before = self.snapshot(messages.len() as u32);
        let keep = self.config.keep_recent_turns as usize;
        let thr_pct = (self.config.threshold * 100.0).round() as u32;
        let reason = req.reason;

        let system: Vec<Message> = messages
            .iter()
            .filter(|m| m.role == MessageRole::System)
            // Drop prior compact hygiene notes so they do not stack forever
            .filter(|m| !m.content.contains("[context auto-compacted") && !m.content.contains("[conversation compacted"))
            .cloned()
            .collect();
        let mut rest: Vec<Message> = messages
            .iter()
            .filter(|m| m.role != MessageRole::System)
            .cloned()
            .collect();

        // Build a structural summary of what we are about to drop (Grok-style retain signal)
        let fold_before = rest.len().saturating_sub(keep);
        let mut summary_bits: Vec<String> = Vec::new();
        for (i, m) in rest.iter().enumerate() {
            if i >= fold_before {
                break;
            }
            match m.role {
                MessageRole::User => {
                    let t: String = m.content.chars().take(80).collect();
                    summary_bits.push(format!("user: {t}"));
                }
                MessageRole::Assistant if !m.content.is_empty() => {
                    let t: String = m.content.chars().take(60).collect();
                    summary_bits.push(format!("assistant: {t}"));
                }
                MessageRole::Tool => {
                    let name = m.name.as_deref().unwrap_or("tool");
                    summary_bits.push(format!("tool:{name}"));
                }
                _ => {}
            }
            if summary_bits.len() >= 12 {
                break;
            }
        }

        // Fold older tool / long assistant content (Grok pruning: head+tail soft-trim style)
        const COMPACT_HEAD: usize = 400;
        const COMPACT_TAIL: usize = 200;
        let rest_len = rest.len();
        for (i, m) in rest.iter_mut().enumerate() {
            if i < fold_before {
                if m.role == MessageRole::Tool && m.content.len() > 300 {
                    let chars: Vec<char> = m.content.chars().collect();
                    let head: String = chars.iter().take(COMPACT_HEAD).collect();
                    let tail: String = chars
                        .iter()
                        .rev()
                        .take(COMPACT_TAIL)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    m.content = format!(
                        "[compacted tool result — re-run tools_search/tools_execute if needed]\n{head}\n…\n{tail}"
                    );
                }
                if m.role == MessageRole::Assistant && m.content.len() > 1_500 {
                    let preview: String = m.content.chars().take(500).collect();
                    m.content = format!("[compacted assistant text]\n{preview}…");
                }
                if !self.config.keep_latest_thinking || i + 1 < rest_len {
                    m.thinking = None;
                }
            }
        }

        // Hard drop older turns — Grok discards early history past the keep window.
        // Auto-compact keeps a tighter residual; manual `/compact` keeps a bit more.
        let mut dropped = 0usize;
        let hard_cap = match reason {
            CompactReason::Threshold | CompactReason::PreFlight => keep.saturating_mul(2).max(4),
            CompactReason::Manual => keep.saturating_mul(3).max(6),
            CompactReason::ModelSwitch => keep.saturating_mul(2).max(4),
        };
        if rest.len() > hard_cap {
            let drop_n = rest.len() - hard_cap;
            dropped = rest.drain(..drop_n).count();
        }

        // Fold remaining large tool blobs except the last exchange
        let fold_tail = rest.len().saturating_sub(2);
        for (i, m) in rest.iter_mut().enumerate() {
            if i >= fold_tail {
                break;
            }
            if m.role == MessageRole::Tool && m.content.len() > 800 {
                let preview: String = m.content.chars().take(180).collect();
                m.content = format!("[compacted tool result]\n{preview}…");
            }
        }

        if self.config.keep_latest_thinking {
            let mut seen_assistant = false;
            for m in rest.iter_mut().rev() {
                if m.role == MessageRole::Assistant {
                    if seen_assistant {
                        m.thinking = None;
                    } else {
                        seen_assistant = true;
                    }
                }
            }
        }

        let keep_note = req
            .keep_note
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| format!(" User preserve note: {s}"))
            .unwrap_or_default();

        let summary_block = if summary_bits.is_empty() {
            String::new()
        } else {
            format!(
                "\nEarlier topics (compressed): {}",
                summary_bits.join(" · ")
            )
        };

        let trigger = match reason {
            CompactReason::Threshold | CompactReason::PreFlight => "auto",
            CompactReason::Manual => "manual",
            CompactReason::ModelSwitch => "model_switch",
        };

        messages.clear();
        messages.extend(system);
        // Grok-style compact notice: user + agent see that history was compressed
        messages.push(Message::system(format!(
            "[conversation compacted · trigger={trigger} · threshold={thr_pct}% of context_window · \
dropped_msgs={dropped} · before={} tok ({:.0}%) → reclaimed for new work.{keep_note}{summary_block} \
Prefer tools_search → tools_execute to re-fetch details; do not re-expand compacted blobs.]",
            before.used_tokens,
            before.percent,
        )));
        messages.extend(rest);

        self.compacted = true;
        self.compact_count = self.compact_count.saturating_add(1);
        self.estimated_tokens = Self::estimate_messages(messages);
        self.last_usage = None;
        let after = self.snapshot(messages.len() as u32);
        (before, after)
    }

    pub fn store_artifact(&mut self, id: impl Into<String>, data: serde_json::Value) {
        self.artifacts.insert(id.into(), data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::Message;

    #[test]
    fn default_threshold_matches_grok_85_percent() {
        let cfg = CompactConfig::default();
        assert!((cfg.threshold - 0.85).abs() < f32::EPSILON);
        assert!(cfg.auto);
    }

    #[test]
    fn auto_compact_trips_at_eighty_five_percent_of_full_window() {
        let mut cfg = CompactConfig::default();
        let mut cm = ContextManager::new("test", 10_000, cfg.clone());
        // reserved must NOT prevent trip: 8500/10000 = 85% of full window
        cm.config.reserved_output_tokens = 4000;
        cm.estimated_tokens = 8500;
        assert!(cm.should_compact());
        cm.estimated_tokens = 8400;
        assert!(!cm.should_compact());

        cfg.auto = true;
        let mut cm = ContextManager::new("test", 1000, cfg);
        cm.config.reserved_output_tokens = 0;
        let mut msgs = vec![Message::system("sys")];
        for _ in 0..20 {
            msgs.push(Message::user("x".repeat(200)));
            msgs.push(Message::assistant("y".repeat(200)));
            msgs.push(Message::tool_result("1", "t", "z".repeat(400)));
        }
        cm.observe_messages(&msgs);
        assert!(cm.should_compact());
        let (_b, after) = cm.compact_with(
            &mut msgs,
            CompactRequest {
                reason: CompactReason::Threshold,
                keep_note: Some("keep dns facts".into()),
            },
        );
        assert!(after.compacted);
        assert!(msgs.iter().any(|m| m.content.contains("preserve note: keep dns facts")));
        assert!(msgs.iter().any(|m| m.content.contains("trigger=auto")));
    }

    #[test]
    fn soft_zone_before_hard_threshold() {
        let mut cm = ContextManager::new("test", 10_000, CompactConfig::default());
        // hard at 8500; soft starts at 8500-4000=4500
        cm.estimated_tokens = 5000;
        assert!(cm.in_soft_zone());
        assert!(!cm.should_compact());
        assert!(cm.should_soft_fold());
        cm.estimated_tokens = 8600;
        assert!(cm.should_compact());
        assert!(!cm.should_soft_fold());
    }

    #[test]
    fn soft_fold_trims_old_tool_head_and_tail() {
        let mut cm = ContextManager::new("test", 100_000, CompactConfig::default());
        // keep_recent_turns=6 → first tool messages should fold
        let big = format!("{}MID{}", "H".repeat(2000), "T".repeat(2000));
        let mut msgs = vec![
            Message::system("sys"),
            Message::user("u1"),
            Message::tool_result("1", "dns", big.clone()),
            Message::user("u2"),
            Message::assistant("a2"),
            Message::user("u3"),
            Message::assistant("a3"),
            Message::user("u4"),
            Message::assistant("a4"),
            Message::user("recent"),
            Message::assistant("keep me"),
        ];
        cm.observe_messages(&msgs);
        // Force soft zone without hard compact
        cm.estimated_tokens = 5000;
        cm.config.threshold = 0.85;
        // context window large so 5000 is soft not hard... actually 5000/100000 is tiny.
        // Set window so soft zone includes estimated_tokens
        cm.context_window = 10_000;
        assert!(cm.should_soft_fold());
        let n = cm.soft_fold_tools(&mut msgs);
        assert!(n >= 1);
        let tool = msgs.iter().find(|m| m.role == MessageRole::Tool).unwrap();
        assert!(tool.content.contains("soft-trimmed"));
        assert!(tool.content.contains("H"));
        assert!(tool.content.contains("T"));
        assert!(tool.content.len() < big.len());
    }

    #[test]
    fn auto_off_never_compacts() {
        let mut cfg = CompactConfig::default();
        cfg.auto = false;
        cfg.threshold = 0.10;
        let mut cm = ContextManager::new("test", 1000, cfg);
        cm.estimated_tokens = 900;
        assert!(!cm.should_compact());
        assert!(!cm.should_soft_fold());
    }

    #[test]
    fn manual_compact_keeps_more_turns_than_auto() {
        let cfg = CompactConfig {
            keep_recent_turns: 4,
            auto: true,
            ..CompactConfig::default()
        };
        let mut msgs_auto = Vec::new();
        let mut msgs_manual = Vec::new();
        msgs_auto.push(Message::system("sys"));
        msgs_manual.push(Message::system("sys"));
        for i in 0..20 {
            let u = Message::user(format!("user turn {i}"));
            let a = Message::assistant(format!("asst turn {i}"));
            msgs_auto.push(u.clone());
            msgs_auto.push(a.clone());
            msgs_manual.push(u);
            msgs_manual.push(a);
        }
        let mut cm_auto = ContextManager::new("t", 200_000, cfg.clone());
        let mut cm_manual = ContextManager::new("t", 200_000, cfg);
        cm_auto.compact(&mut msgs_auto, CompactReason::Threshold);
        cm_manual.compact(&mut msgs_manual, CompactReason::Manual);
        let non_sys = |m: &[Message]| m.iter().filter(|x| x.role != MessageRole::System).count();
        // Manual hard_cap = keep*3=12; auto hard_cap = keep*2=8
        assert!(non_sys(&msgs_manual) >= non_sys(&msgs_auto));
        assert!(msgs_auto.iter().any(|m| m.content.contains("trigger=auto")));
        assert!(msgs_manual.iter().any(|m| m.content.contains("trigger=manual")));
    }
}
