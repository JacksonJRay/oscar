//! Input bar modes: normal chat vs secure credential entry.
//! Idle placeholder tips cycle while the user has not typed (Grok Build–style).

use oscar_core::{AuthRequest, SecretKind};
use std::time::{Duration, Instant};

/// How long each empty-input tip stays visible before rotating.
pub const IDLE_HINT_INTERVAL: Duration = Duration::from_millis(3800);

/// Cycling help tooltips shown in the input bar when empty (chat, normal mode).
pub const IDLE_INPUT_HINTS: &[&str] = &[
    "Ask about multi-cloud DNS, network paths, or k8s…",
    "Type /help · /provider for LLM setup · /settings (Ctrl+,)",
    "Input bar: Ctrl+A start · Ctrl+E end · Ctrl+U clear",
    "Discover tools via Code Mode: agent uses tools_search then tools_execute",
    "Sync inventory: oscar inventory sync --cloud aws --kind dns",
    "Private DNS map: ask about forwarding or /mcp for external tools",
    "Identities: /identities or Ctrl+I · check what oscar can reach",
    "Thinking: /thinking on · status bar shows ctx current/max (%)",
    "Context: status bar = used / max (percent%) · /context for full breakdown",
    "CNI drops? Ask why a pod cannot reach a service (Hubble / Calico tools)",
    "Mode is read-only by default · /mode or Settings → Agent for write",
    "MCP servers mount as mcp.<server>.<tool> — not dumped into the prompt",
    "Compact: /compact or /compact keep <note> · auto at 85% of window (Grok-style)",
    "Chat history auto-saves · /history · /new · /resume <id>",
    "Scroll: PgUp older · PgDn/End newest · scrollback capped for speed",
    "Skills: /skills then /skill least-privilege-iam (or network-vlsm-path)",
];

/// Rotating placeholder state for the empty input field.
#[derive(Debug, Clone)]
pub struct IdleHintRotator {
    pub index: usize,
    last_advance: Instant,
}

impl Default for IdleHintRotator {
    fn default() -> Self {
        Self {
            index: 0,
            last_advance: Instant::now(),
        }
    }
}

impl IdleHintRotator {
    pub fn current(&self) -> &'static str {
        IDLE_INPUT_HINTS[self.index % IDLE_INPUT_HINTS.len()]
    }

    /// Advance when the input is idle long enough. Returns true if the tip changed.
    pub fn tick(&mut self, idle: bool) -> bool {
        if !idle {
            // Keep timer fresh so the next empty pause starts a full interval
            self.last_advance = Instant::now();
            return false;
        }
        if self.last_advance.elapsed() >= IDLE_HINT_INTERVAL {
            self.index = (self.index + 1) % IDLE_INPUT_HINTS.len();
            self.last_advance = Instant::now();
            true
        } else {
            false
        }
    }

    /// Optional: nudge to a new tip immediately (e.g. after sending a message).
    pub fn next(&mut self) {
        self.index = (self.index + 1) % IDLE_INPUT_HINTS.len();
        self.last_advance = Instant::now();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Secure {
        auth: AuthRequest,
        kind_index: usize,
        buffer: String,
    },
}

impl InputMode {
    pub fn secure(auth: AuthRequest) -> Self {
        Self::Secure {
            auth,
            kind_index: 0,
            buffer: String::new(),
        }
    }

    pub fn is_secure(&self) -> bool {
        matches!(self, InputMode::Secure { .. })
    }

    pub fn current_kind(&self) -> Option<SecretKind> {
        match self {
            InputMode::Secure { auth, kind_index, .. } => auth.kinds.get(*kind_index).copied(),
            InputMode::Normal => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_non_empty_and_rotate() {
        assert!(!IDLE_INPUT_HINTS.is_empty());
        let mut r = IdleHintRotator::default();
        let first = r.current();
        r.next();
        assert_ne!(r.current(), first);
        // typing resets interval without advancing
        assert!(!r.tick(false));
        assert_eq!(r.current(), IDLE_INPUT_HINTS[1 % IDLE_INPUT_HINTS.len()]);
    }
}
