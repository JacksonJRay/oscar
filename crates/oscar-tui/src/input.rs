//! Input bar modes: normal chat vs secure credential entry.
//! Idle placeholder tips cycle while the user has not typed (Grok Build–style).
//!
//! Composer layout matches Grok Build: soft-wrap long lines, grow the bar, and
//! support hard newlines (Shift+Enter / Alt+Enter, or Enter in multiline mode).

use oscar_core::{AuthRequest, SecretKind};
use std::time::{Duration, Instant};

/// How long each empty-input tip stays visible before rotating.
pub const IDLE_HINT_INTERVAL: Duration = Duration::from_millis(3800);

/// Prefix shown on the first visual row of the composer (`"> "` = 2 cols).
pub const INPUT_PREFIX: &str = "> ";
/// Continuation indent for wrapped / subsequent rows (same width as prefix).
pub const INPUT_CONT: &str = "  ";
/// Columns taken by [`INPUT_PREFIX`] / [`INPUT_CONT`].
pub const INPUT_PREFIX_COLS: usize = 2;
/// Cap grown composer height (inner content rows, excluding borders).
pub const INPUT_MAX_INNER_ROWS: u16 = 12;
/// Floor for composer content rows when focused.
pub const INPUT_MIN_INNER_ROWS: u16 = 1;

/// Cycling help tooltips shown in the input bar when empty (chat, normal mode).
pub const IDLE_INPUT_HINTS: &[&str] = &[
    "Ask about multi-cloud DNS, network paths, or k8s…",
    "Type /help · /model to switch models · /provider · /settings (Ctrl+,)",
    "Grok primary: oscar auth login (OAuth) · multi-provider: load keys then /model",
    "Tab/Space: focus · ↑↓ select entry · y copy · Esc cancel · Esc Esc clear · /quit exit",
    "Input: Shift+Enter newline · Ctrl+M multiline · Ctrl+A/E · Ctrl+U clear · Ctrl+V paste",
    "Long prompts wrap and grow the bar (Grok-style) · ←→↑↓ move · Home/End line · Del",
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
    "Each launch is a new chat · /resume to browse previous sessions · /new",
    "Scroll: wheel/Ctrl+↑↓ rows · PgUp/PgDn page · Ctrl+U/D half · End newest",
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

// ── Composer soft-wrap layout (Grok parity) ─────────────────────────────────

/// One visual row of the multi-line / wrapped composer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRow {
    /// Char index in the full buffer where this row's content starts.
    pub start: usize,
    /// Display text (never includes a trailing hard `\n`).
    pub text: String,
}

impl InputRow {
    pub fn display_len(&self) -> usize {
        self.text.chars().count()
    }
}

/// Soft-wrap `text` into visual rows of at most `inner_width` columns.
///
/// `inner_width` is the width available **after** the 2-col `> `/`  ` prefix.
/// Hard newlines always break. Prefer breaking at whitespace (Grok-style);
/// only split mid-word when a single token exceeds `inner_width`.
/// Empty buffer yields a single empty row.
///
/// Cursor fidelity: each row's `text` is exactly `chars[start .. next_start)`
/// excluding a hard `\n` (which is not shown but advances `next_start`).
pub fn layout_input_rows(text: &str, inner_width: usize) -> Vec<InputRow> {
    let width = inner_width.max(1);
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return vec![InputRow {
            start: 0,
            text: String::new(),
        }];
    }

    let mut rows: Vec<InputRow> = Vec::new();
    let mut row_start = 0usize;
    let mut i = 0usize;
    // Char index of the last whitespace included on the current row.
    let mut last_ws: Option<usize> = None;

    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            let text: String = chars[row_start..i].iter().collect();
            rows.push(InputRow {
                start: row_start,
                text,
            });
            i += 1;
            row_start = i;
            last_ws = None;
            continue;
        }

        let col = i - row_start;
        if col >= width {
            // Word-wrap: break after last whitespace on this row if any (and not at row start).
            let break_at = last_ws
                .filter(|&ws| ws >= row_start && ws + 1 > row_start)
                .map(|ws| ws + 1); // exclusive end after the space
            if let Some(end) = break_at {
                if end > row_start && end <= i {
                    let text: String = chars[row_start..end].iter().collect();
                    rows.push(InputRow {
                        start: row_start,
                        text,
                    });
                    row_start = end;
                    last_ws = None;
                    // i stays; re-measure current char on the new row
                    continue;
                }
            }
            // Mid-token hard split at `i` (current char starts next row).
            if i > row_start {
                let text: String = chars[row_start..i].iter().collect();
                rows.push(InputRow {
                    start: row_start,
                    text,
                });
                row_start = i;
                last_ws = None;
                continue;
            }
        }

        if c.is_whitespace() {
            last_ws = Some(i);
        }
        i += 1;
    }

    // Final row (including empty row after trailing newline).
    let text: String = chars[row_start..].iter().collect();
    rows.push(InputRow {
        start: row_start,
        text,
    });
    rows
}

/// Map a char cursor index → (visual row, column within row content).
///
/// Cursor on a hard newline sits at the end of the preceding visual row.
pub fn cursor_row_col(rows: &[InputRow], cursor: usize, text_char_len: usize) -> (usize, usize) {
    if rows.is_empty() {
        return (0, 0);
    }
    let cursor = cursor.min(text_char_len);
    let mut row_idx = 0usize;
    for (i, r) in rows.iter().enumerate() {
        if r.start <= cursor {
            row_idx = i;
        }
    }
    let row = &rows[row_idx];
    let col = cursor.saturating_sub(row.start).min(row.display_len());
    (row_idx, col)
}

/// Map (visual row, column) → char cursor index.
pub fn row_col_to_cursor(rows: &[InputRow], row: usize, col: usize, text_char_len: usize) -> usize {
    if rows.is_empty() {
        return 0;
    }
    let row = row.min(rows.len() - 1);
    let r = &rows[row];
    let col = col.min(r.display_len());
    (r.start + col).min(text_char_len)
}

/// Move the cursor by `drow` visual rows, preserving column when possible.
pub fn move_cursor_visual(
    rows: &[InputRow],
    cursor: usize,
    text_char_len: usize,
    drow: i32,
) -> usize {
    if rows.is_empty() || drow == 0 {
        return cursor.min(text_char_len);
    }
    let (r, c) = cursor_row_col(rows, cursor, text_char_len);
    let nr = (r as i32 + drow).clamp(0, rows.len() as i32 - 1) as usize;
    row_col_to_cursor(rows, nr, c, text_char_len)
}

/// Start-of-line (current visual row) char index.
pub fn line_home(rows: &[InputRow], cursor: usize, text_char_len: usize) -> usize {
    let (r, _) = cursor_row_col(rows, cursor, text_char_len);
    rows.get(r).map(|row| row.start).unwrap_or(0)
}

/// End-of-line (current visual row) char index.
pub fn line_end(rows: &[InputRow], cursor: usize, text_char_len: usize) -> usize {
    let (r, _) = cursor_row_col(rows, cursor, text_char_len);
    row_col_to_cursor(rows, r, usize::MAX, text_char_len)
}

/// How many inner content rows the composer should occupy given buffer layout,
/// terminal height, and a max fraction of the screen.
pub fn composer_inner_height(row_count: usize, term_height: u16) -> u16 {
    let max_by_screen = (term_height / 3).max(INPUT_MIN_INNER_ROWS).min(INPUT_MAX_INNER_ROWS);
    let needed = (row_count as u16).max(INPUT_MIN_INNER_ROWS);
    needed.min(max_by_screen)
}

/// Keep `cursor_row` visible within `visible` rows starting at `scroll`.
pub fn ensure_input_scroll(scroll: usize, cursor_row: usize, total_rows: usize, visible: usize) -> usize {
    if total_rows <= visible {
        return 0;
    }
    let visible = visible.max(1);
    let mut scroll = scroll.min(total_rows.saturating_sub(visible));
    if cursor_row < scroll {
        scroll = cursor_row;
    } else if cursor_row >= scroll + visible {
        scroll = cursor_row + 1 - visible;
    }
    scroll
}

/// Content width inside the input border for a given pane width.
pub fn input_inner_width(pane_width: u16) -> usize {
    // borders (2) + prefix cols (2)
    pane_width.saturating_sub(2 + INPUT_PREFIX_COLS as u16).max(8) as usize
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

    #[test]
    fn soft_wrap_long_line() {
        let text: String = (0..50).map(|_| 'a').collect();
        let rows = layout_input_rows(&text, 20);
        assert!(rows.len() >= 3, "expected multiple wrap rows, got {}", rows.len());
        assert_eq!(rows[0].start, 0);
        assert_eq!(rows[0].display_len(), 20);
        assert_eq!(rows[1].start, 20);
        let joined: String = rows.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(joined, text);
    }

    #[test]
    fn soft_wrap_prefers_word_boundary() {
        let text = "hello world foobar";
        let rows = layout_input_rows(text, 12);
        // Should not split "hello" or "world" mid-token.
        for r in &rows {
            assert!(
                !r.text.ends_with("hel") && !r.text.starts_with("lo "),
                "mid-word split: {:?}",
                r.text
            );
        }
        let joined: String = rows.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(joined, text);
        assert!(rows.len() >= 2);
    }

    #[test]
    fn hard_newline_splits() {
        let rows = layout_input_rows("hello\nworld", 40);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].text, "hello");
        assert_eq!(rows[1].text, "world");
        assert_eq!(rows[1].start, 6);
        // cursor on '\n' (index 5) sits at end of first row
        let (r, c) = cursor_row_col(&rows, 5, 11);
        assert_eq!((r, c), (0, 5));
        // cursor after newline at start of second
        let (r, c) = cursor_row_col(&rows, 6, 11);
        assert_eq!((r, c), (1, 0));
    }

    #[test]
    fn trailing_newline_makes_empty_row() {
        let rows = layout_input_rows("ab\n", 40);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].text, "ab");
        assert_eq!(rows[1].text, "");
        assert_eq!(rows[1].start, 3);
    }

    #[test]
    fn move_visual_preserves_column() {
        let rows = layout_input_rows("abcd\nefgh", 40);
        // cursor on 'c' (index 2)
        let down = move_cursor_visual(&rows, 2, 9, 1);
        assert_eq!(down, 7); // 'g'
        let up = move_cursor_visual(&rows, down, 9, -1);
        assert_eq!(up, 2);
    }

    #[test]
    fn scroll_keeps_cursor_visible() {
        assert_eq!(ensure_input_scroll(0, 5, 10, 3), 3); // 5 >= 0+3 → scroll to 3
        assert_eq!(ensure_input_scroll(4, 1, 10, 3), 1); // 1 < 4 → scroll to 1
        assert_eq!(ensure_input_scroll(0, 0, 2, 5), 0); // fits
    }

    #[test]
    fn composer_height_clamps() {
        assert_eq!(composer_inner_height(1, 40), 1);
        assert_eq!(composer_inner_height(20, 30), 10); // min(20, min(12, 30/3=10)) = 10
        assert_eq!(composer_inner_height(20, 90), 12); // max 12
    }
}
