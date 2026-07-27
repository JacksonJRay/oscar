use crate::clipboard;
use crate::identities::IdentitiesPane;
use crate::input::{IdleHintRotator, InputMode};
use crate::provider_pane::{ProviderPane, ProviderPaneAction};
use crate::settings::{SettingsPane, ToolCatalogEntry};
use crate::ui;
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use oscar_core::config::OscarConfig;
use oscar_core::events::{AgentEvent, ContextSnapshot};
use oscar_core::{AuthRequest, ExecutionMode, TranscriptLine};
use oscar_identity::{
    build_identity_inventory, build_identity_inventory_quick, BinaryInventory, IdentityInventory,
    ProfileStore,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub provider: String,
    pub model: String,
    pub mode: ExecutionMode,
    pub show_thinking: bool,
    pub profile_count: usize,
    /// Snapshot of config for the settings pane.
    pub oscar_config: OscarConfig,
    /// First-class tool catalog for toggles.
    pub tool_catalog: Vec<ToolCatalogEntry>,
    /// Path to profiles.toml for identity probes.
    pub profiles_path: PathBuf,
    /// False when LLM key/provider is missing — TUI opens Provider setup.
    pub provider_ready: bool,
}

#[derive(Debug, Clone)]
pub struct ChatLine {
    pub kind: LineKind,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    User,
    Assistant,
    Thinking,
    Tool,
    System,
    Error,
}

/// Max lines kept in the TUI buffer (oldest dropped). Keeps resume/load fast.
pub const MAX_TRANSCRIPT_LINES: usize = 1_500;
/// Max lines you can scroll back from the bottom (Grok Build–style cutoff).
pub const MAX_SCROLL_BACK_LINES: usize = 400;

/// Live agent activity for status / Grok Build–style chrome.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AgentActivity {
    #[default]
    Idle,
    /// Model generating answer text.
    Answering,
    /// Model reasoning channel streaming.
    Thinking,
    /// First-class tool running.
    Tool {
        id: String,
    },
}

pub enum View {
    Chat,
    Settings(SettingsPane),
    Identities(IdentitiesPane),
    /// Dedicated LLM provider setup (default, keys, URLs, custom).
    Provider(ProviderPane),
}

/// Which controllable pane owns keyboard navigation (Grok Build–style).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaneFocus {
    /// Composer / input bar (default).
    #[default]
    Prompt,
    /// Chat scrollback — select lines, highlight, copy.
    Scrollback,
}

/// Inclusive line selection in the chat scrollback (`lines` indices).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineSelection {
    pub anchor: usize,
    pub cursor: usize,
}

impl LineSelection {
    pub fn single(idx: usize) -> Self {
        Self {
            anchor: idx,
            cursor: idx,
        }
    }

    pub fn range(&self) -> (usize, usize) {
        (self.anchor.min(self.cursor), self.anchor.max(self.cursor))
    }

    pub fn contains(&self, idx: usize) -> bool {
        let (a, b) = self.range();
        idx >= a && idx <= b
    }

    pub fn line_count(&self) -> usize {
        let (a, b) = self.range();
        b.saturating_sub(a) + 1
    }
}

pub struct App {
    pub config: AppConfig,
    pub lines: Vec<ChatLine>,
    pub input: String,
    /// Cursor position in **chars** within `input` (or secure buffer).
    pub input_cursor: usize,
    pub input_mode: InputMode,
    pub status: String,
    pub context: Option<ContextSnapshot>,
    pub streaming: bool,
    pub show_thinking: bool,
    pub should_quit: bool,
    pub view: View,
    /// User messages / slash commands for the host to process.
    pub pending_user: Option<String>,
    /// Submitted secret when secure mode completes one field.
    pub pending_secret: Option<(AuthRequest, oscar_core::SecretKind, String)>,
    /// Config to persist after settings close.
    pub pending_config_save: Option<OscarConfig>,
    /// Request a live identity validity probe (blocking work offloaded in run_loop).
    pub pending_identity_probe: bool,
    /// When true, show expanded detail for selected identity.
    pub identity_detail: bool,
    pub cancel_requested: bool,
    /// Cycling empty-input help tips (Grok Build–style).
    pub idle_hint: IdleHintRotator,
    /// Active chat session id (persisted under ~/.config/oscar/sessions/).
    pub session_id: String,
    pub session_title: String,
    /// Request host to persist session snapshot.
    pub pending_session_save: bool,
    /// Request host to start a new session / resume id.
    pub pending_session_action: Option<SessionAction>,
    /// Chat scroll: **0 = pinned to bottom** (newest). Higher = look further back.
    pub chat_scroll: usize,
    /// When true, new lines keep the viewport pinned to the bottom.
    pub stick_to_bottom: bool,
    /// What the agent is doing right now (thinking / tool / answering).
    pub activity: AgentActivity,
    /// Spinner frame index for live activity.
    pub activity_tick: usize,
    /// Controllable pane focus (prompt vs scrollback).
    pub pane_focus: PaneFocus,
    /// Highlighted line range when scrollback is focused (or after click).
    pub selection: Option<LineSelection>,
    /// Brief status flash after copy/paste (also pushed as a system line when useful).
    pub copy_flash: Option<String>,
    /// Cached layout: last drawn chat pane rect (for mouse hit-testing).
    pub chat_area: Option<(u16, u16, u16, u16)>, // x,y,w,h
    /// Cached layout: last drawn input pane rect.
    pub input_area: Option<(u16, u16, u16, u16)>,
    /// True while a thinking stream is open (header + body).
    thinking_open: bool,
    /// Chars received in the current thinking block.
    thinking_chars: usize,
}

#[derive(Debug, Clone)]
pub enum SessionAction {
    New,
    List,
    Resume(String),
    Delete(String),
}

impl App {
    pub fn new(config: AppConfig) -> Self {
        let show_thinking = config.show_thinking;
        let mut app = Self {
            config,
            lines: vec![ChatLine {
                kind: LineKind::System,
                text: "oscar — multi-cloud native dredger. Type a question, /settings, or /help."
                    .into(),
            }],
            input: String::new(),
            input_cursor: 0,
            input_mode: InputMode::Normal,
            status: String::new(),
            context: None,
            streaming: false,
            show_thinking,
            should_quit: false,
            view: View::Chat,
            pending_user: None,
            pending_secret: None,
            pending_config_save: None,
            pending_identity_probe: false,
            identity_detail: false,
            cancel_requested: false,
            idle_hint: IdleHintRotator::default(),
            session_id: String::new(),
            session_title: "New chat".into(),
            pending_session_save: false,
            pending_session_action: None,
            chat_scroll: 0,
            stick_to_bottom: true,
            activity: AgentActivity::Idle,
            activity_tick: 0,
            pane_focus: PaneFocus::Prompt,
            selection: None,
            copy_flash: None,
            chat_area: None,
            input_area: None,
            thinking_open: false,
            thinking_chars: 0,
        };
        app.trim_transcript();
        app.pin_to_bottom();
        app.refresh_status();
        if !app.config.provider_ready {
            app.open_provider_setup(
                "No LLM provider key configured — pick a provider and paste your API key (secure bar).",
            );
        }
        app
    }

    /// Open dedicated Provider setup pane (first run / missing key / /provider).
    pub fn open_provider_setup(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        // Never leave chat stuck in streaming when forcing setup.
        self.streaming = false;
        self.activity = AgentActivity::Idle;
        self.cancel_requested = false;
        self.push_line(LineKind::System, reason);
        self.push_line(
            LineKind::System,
            "Providers: ↑↓ pick · → actions · Enter run · set default · open console · paste key. Chat disabled until a key is stored.",
        );
        let pane = ProviderPane::open(self.config.oscar_config.clone());
        self.view = View::Provider(pane);
    }

    pub fn close_provider_pane(&mut self, save: bool) {
        if let View::Provider(pane) = std::mem::replace(&mut self.view, View::Chat) {
            if save || pane.dirty {
                self.apply_config(pane.config.clone());
                self.pending_config_save = Some(pane.config);
                self.push_line(
                    LineKind::System,
                    format!(
                        "Provider settings saved · default=`{}` · ready={}",
                        self.config.provider,
                        self.config.provider_ready
                    ),
                );
            } else {
                self.push_line(LineKind::System, "Provider setup closed.");
            }
        }
    }

    fn begin_provider_key_paste(&mut self, provider_id: String) {
        use oscar_core::{Cloud, SecretKind};
        self.config.oscar_config.provider.id = provider_id.clone();
        self.config.provider = provider_id.clone();
        let auth = AuthRequest::new(
            Cloud::Multi,
            format!("Paste API key for LLM provider `{provider_id}`"),
            vec![SecretKind::ApiKey],
        )
        .profile(format!("provider:{provider_id}"))
        .with_guidance(
            "Key is stored in the OS keychain only. It is never shown in chat or sent to the agent transcript.",
        )
        .with_hints([
            format!("oscar auth provider-key --provider {provider_id} --key-file …"),
            "Or paste here in the secure bar (masked)".into(),
        ]);
        self.input_mode = InputMode::secure(auth);
        self.input_cursor = 0;
        self.push_line(
            LineKind::System,
            format!(
                "SECURE: paste API key for `{provider_id}` (Ctrl+U clear · Esc cancel). Agent will not see the value."
            ),
        );
    }

    // ── input bar helpers (cursor + readline-style chords) ─────────────────

    fn input_char_len(s: &str) -> usize {
        s.chars().count()
    }

    fn byte_index_at(s: &str, char_idx: usize) -> usize {
        s.char_indices()
            .nth(char_idx)
            .map(|(i, _)| i)
            .unwrap_or(s.len())
    }

    fn clamp_cursor(&mut self) {
        let len = match &self.input_mode {
            InputMode::Secure { buffer, .. } => Self::input_char_len(buffer),
            InputMode::Normal => Self::input_char_len(&self.input),
        };
        if self.input_cursor > len {
            self.input_cursor = len;
        }
    }

    fn input_insert_char(&mut self, c: char) {
        match &mut self.input_mode {
            InputMode::Secure { buffer, .. } => {
                let i = Self::byte_index_at(buffer, self.input_cursor);
                buffer.insert(i, c);
                self.input_cursor += 1;
            }
            InputMode::Normal => {
                let i = Self::byte_index_at(&self.input, self.input_cursor);
                self.input.insert(i, c);
                self.input_cursor += 1;
            }
        }
    }

    fn input_backspace(&mut self) {
        if self.input_cursor == 0 {
            return;
        }
        match &mut self.input_mode {
            InputMode::Secure { buffer, .. } => {
                let start = Self::byte_index_at(buffer, self.input_cursor - 1);
                let end = Self::byte_index_at(buffer, self.input_cursor);
                buffer.replace_range(start..end, "");
                self.input_cursor -= 1;
            }
            InputMode::Normal => {
                let start = Self::byte_index_at(&self.input, self.input_cursor - 1);
                let end = Self::byte_index_at(&self.input, self.input_cursor);
                self.input.replace_range(start..end, "");
                self.input_cursor -= 1;
            }
        }
    }

    fn input_clear(&mut self) {
        match &mut self.input_mode {
            InputMode::Secure { buffer, .. } => buffer.clear(),
            InputMode::Normal => self.input.clear(),
        }
        self.input_cursor = 0;
    }

    fn input_home(&mut self) {
        self.input_cursor = 0;
    }

    fn input_end(&mut self) {
        self.input_cursor = match &self.input_mode {
            InputMode::Secure { buffer, .. } => Self::input_char_len(buffer),
            InputMode::Normal => Self::input_char_len(&self.input),
        };
    }

    /// Advance spinner when agent is active (call from frame loop).
    pub fn tick_activity(&mut self) {
        if !matches!(self.activity, AgentActivity::Idle) {
            self.activity_tick = self.activity_tick.wrapping_add(1);
        }
    }

    fn spinner_frame(&self) -> char {
        const FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        FRAMES[self.activity_tick % FRAMES.len()]
    }

    /// Status fragment for live agent work (Grok Build–style).
    pub fn activity_label(&self) -> Option<String> {
        let sp = self.spinner_frame();
        match &self.activity {
            AgentActivity::Idle => None,
            AgentActivity::Answering => Some(format!("{sp} answering")),
            AgentActivity::Thinking => Some(format!("{sp} thinking")),
            AgentActivity::Tool { id } => {
                let short = if id.len() > 28 {
                    format!("{}…", &id[..27])
                } else {
                    id.clone()
                };
                Some(format!("{sp} tool {short}"))
            }
        }
    }

    /// Restore display transcript from a saved session.
    /// Always pins viewport to the **bottom** (newest) so loading history does not leave the user mid-scroll.
    pub fn load_transcript(&mut self, lines: &[TranscriptLine], session_id: &str, title: &str) {
        self.session_id = session_id.into();
        self.session_title = title.into();
        // Keep only the newest window of lines for speed (cutoff from the start / oldest).
        let mapped: Vec<ChatLine> = lines
            .iter()
            .map(|l| ChatLine {
                kind: match l.kind.as_str() {
                    "user" => LineKind::User,
                    "assistant" => LineKind::Assistant,
                    "thinking" => LineKind::Thinking,
                    "tool" => LineKind::Tool,
                    "error" => LineKind::Error,
                    _ => LineKind::System,
                },
                text: l.text.clone(),
            })
            .collect();
        let start = mapped.len().saturating_sub(MAX_TRANSCRIPT_LINES);
        self.lines = mapped[start..].to_vec();
        if self.lines.is_empty() {
            self.lines.push(ChatLine {
                kind: LineKind::System,
                text: format!("Resumed session `{session_id}` — {title}"),
            });
        } else if start > 0 {
            self.lines.insert(
                0,
                ChatLine {
                    kind: LineKind::System,
                    text: format!(
                        "… {start} older line(s) omitted (scrollback cap {MAX_TRANSCRIPT_LINES}) · showing newest"
                    ),
                },
            );
        }
        // Newest at bottom, no mid-history jump after load
        self.pin_to_bottom();
        self.refresh_status();
    }

    /// Pin chat viewport to newest messages (bottom).
    pub fn pin_to_bottom(&mut self) {
        self.chat_scroll = 0;
        self.stick_to_bottom = true;
    }

    /// Drop oldest lines beyond `MAX_TRANSCRIPT_LINES`.
    pub fn trim_transcript(&mut self) {
        if self.lines.len() > MAX_TRANSCRIPT_LINES {
            let drop_n = self.lines.len() - MAX_TRANSCRIPT_LINES;
            self.lines.drain(0..drop_n);
            // Keep scroll meaningful after trim
            self.chat_scroll = self.chat_scroll.min(self.max_chat_scroll());
        }
    }

    /// Max scroll offset from bottom (hard cutoff for performance).
    pub fn max_chat_scroll(&self) -> usize {
        self.lines
            .len()
            .saturating_sub(1)
            .min(MAX_SCROLL_BACK_LINES)
    }

    /// Scroll chat history: positive = older (up), negative = newer (down toward bottom).
    pub fn scroll_chat(&mut self, delta: i32) {
        if delta == 0 {
            return;
        }
        let max = self.max_chat_scroll() as i32;
        let next = (self.chat_scroll as i32 + delta).clamp(0, max);
        self.chat_scroll = next as usize;
        self.stick_to_bottom = self.chat_scroll == 0;
    }

    /// Focus the prompt (composer). Clears scrollback-only key modes.
    pub fn focus_prompt(&mut self) {
        self.pane_focus = PaneFocus::Prompt;
        // Keep selection highlight visible briefly? Grok clears when typing — keep until leave.
    }

    /// Focus the chat scrollback and ensure a selection exists.
    pub fn focus_scrollback(&mut self) {
        self.pane_focus = PaneFocus::Scrollback;
        if self.selection.is_none() && !self.lines.is_empty() {
            // Prefer newest line (bottom of transcript).
            let idx = self.lines.len() - 1;
            self.selection = Some(LineSelection::single(idx));
            self.ensure_selection_visible();
        }
        self.stick_to_bottom = false;
    }

    pub fn toggle_pane_focus(&mut self) {
        match self.pane_focus {
            PaneFocus::Prompt => self.focus_scrollback(),
            PaneFocus::Scrollback => self.focus_prompt(),
        }
    }

    /// Move selection cursor by `delta` lines. When `extend`, keep anchor (Shift+arrows).
    pub fn move_selection(&mut self, delta: i32, extend: bool) {
        if self.lines.is_empty() {
            return;
        }
        let last = self.lines.len() - 1;
        let cur = self
            .selection
            .map(|s| s.cursor)
            .unwrap_or(last);
        let next = (cur as i32 + delta).clamp(0, last as i32) as usize;
        if extend {
            if let Some(sel) = self.selection.as_mut() {
                sel.cursor = next;
            } else {
                self.selection = Some(LineSelection::single(next));
            }
        } else {
            self.selection = Some(LineSelection::single(next));
        }
        self.ensure_selection_visible();
        self.pane_focus = PaneFocus::Scrollback;
    }

    /// Keep the selection cursor inside the visible viewport by adjusting `chat_scroll`.
    pub fn ensure_selection_visible(&mut self) {
        let Some(sel) = self.selection else {
            return;
        };
        let total = self.lines.len();
        if total == 0 {
            return;
        }
        // Viewport height unknown here — use a conservative 12-line page when scrolling.
        // UI also re-clamps; this keeps cursor roughly on screen for keyboard nav.
        let page = 12usize;
        let cursor = sel.cursor.min(total - 1);
        // Distance from bottom: 0 = last line
        let from_bottom = total - 1 - cursor;
        if from_bottom < self.chat_scroll {
            // Cursor below viewport (newer than scroll window) → scroll down
            self.chat_scroll = from_bottom;
        } else if from_bottom >= self.chat_scroll + page {
            // Cursor above viewport → scroll up so cursor near top
            self.chat_scroll = from_bottom.saturating_sub(page.saturating_sub(1));
        }
        self.chat_scroll = self.chat_scroll.min(self.max_chat_scroll());
        self.stick_to_bottom = self.chat_scroll == 0 && self.pane_focus == PaneFocus::Prompt;
    }

    /// Text for the current selection (or last assistant message if none).
    pub fn selection_text(&self) -> Option<String> {
        if let Some(sel) = self.selection {
            let (a, b) = sel.range();
            if a < self.lines.len() {
                let end = b.min(self.lines.len() - 1);
                let text = self.lines[a..=end]
                    .iter()
                    .map(|l| l.text.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                return Some(text);
            }
        }
        // Fallback: most recent assistant block (contiguous assistant lines from end)
        let mut collected = Vec::new();
        for l in self.lines.iter().rev() {
            if l.kind == LineKind::Assistant {
                collected.push(l.text.as_str());
            } else if !collected.is_empty() {
                break;
            }
        }
        if collected.is_empty() {
            None
        } else {
            collected.reverse();
            Some(collected.join("\n"))
        }
    }

    /// Copy selection (or last assistant) to clipboard + backup.
    pub fn copy_selection(&mut self) {
        let Some(text) = self.selection_text() else {
            self.copy_flash = Some("Nothing to copy".into());
            self.push_line(LineKind::System, "Nothing to copy (no selection / assistant reply).");
            return;
        };
        let outcome = clipboard::copy_text(&text);
        self.copy_flash = Some(outcome.message.clone());
        let n = self.selection.map(|s| s.line_count()).unwrap_or(1);
        self.push_line(
            LineKind::System,
            format!("{} · {n} line(s)", outcome.message),
        );
    }

    /// `/copy` [n] — copy Nth-latest assistant reply (1 = most recent).
    pub fn copy_nth_assistant(&mut self, n: usize) {
        let n = n.max(1);
        let mut blocks: Vec<String> = Vec::new();
        let mut cur: Vec<&str> = Vec::new();
        for l in &self.lines {
            if l.kind == LineKind::Assistant {
                cur.push(l.text.as_str());
            } else if !cur.is_empty() {
                blocks.push(cur.join("\n"));
                cur.clear();
            }
        }
        if !cur.is_empty() {
            blocks.push(cur.join("\n"));
        }
        if blocks.is_empty() {
            self.push_line(LineKind::System, "No assistant replies to copy.");
            return;
        }
        let idx_from_end = n - 1;
        if idx_from_end >= blocks.len() {
            self.push_line(
                LineKind::System,
                format!("Only {} assistant reply block(s).", blocks.len()),
            );
            return;
        }
        let text = &blocks[blocks.len() - 1 - idx_from_end];
        let outcome = clipboard::copy_text(text);
        self.copy_flash = Some(outcome.message.clone());
        self.push_line(
            LineKind::System,
            format!("{} · assistant reply #{n}", outcome.message),
        );
    }

    /// Paste clipboard into the input bar at the cursor.
    pub fn paste_into_input(&mut self) {
        if matches!(self.input_mode, InputMode::Secure { .. }) {
            // Secure: paste as secret buffer (still masked)
            if let Some(text) = clipboard::paste_text() {
                let cleaned = text.trim_end_matches(['\r', '\n']);
                if let InputMode::Secure { buffer, .. } = &mut self.input_mode {
                    // Insert at cursor in buffer
                    let mut chars: Vec<char> = buffer.chars().collect();
                    let pos = self.input_cursor.min(chars.len());
                    for (i, c) in cleaned.chars().enumerate() {
                        chars.insert(pos + i, c);
                    }
                    *buffer = chars.into_iter().collect();
                    self.input_cursor = pos + cleaned.chars().count();
                }
                self.copy_flash = Some("Pasted into secure bar (masked)".into());
            } else {
                self.copy_flash = Some("Clipboard empty / unavailable".into());
            }
            return;
        }
        if let Some(text) = clipboard::paste_text() {
            // Multi-line paste: keep newlines as spaces for single-line bar, or keep \n
            let cleaned = text.replace('\r', "");
            self.input_insert_str(&cleaned);
            self.pane_focus = PaneFocus::Prompt;
            self.copy_flash = Some(format!("Pasted {} chars", cleaned.chars().count()));
        } else {
            self.copy_flash = Some(
                "Clipboard empty — use terminal Shift+Insert or middle-click for PRIMARY".into(),
            );
        }
    }

    /// Insert a string at the input cursor (normal mode).
    pub fn input_insert_str(&mut self, s: &str) {
        if matches!(self.input_mode, InputMode::Secure { .. }) {
            if let InputMode::Secure { buffer, .. } = &mut self.input_mode {
                let mut chars: Vec<char> = buffer.chars().collect();
                let pos = self.input_cursor.min(chars.len());
                for (i, c) in s.chars().enumerate() {
                    chars.insert(pos + i, c);
                }
                *buffer = chars.into_iter().collect();
                self.input_cursor = pos + s.chars().count();
            }
            return;
        }
        let mut chars: Vec<char> = self.input.chars().collect();
        let pos = self.input_cursor.min(chars.len());
        for (i, c) in s.chars().enumerate() {
            chars.insert(pos + i, c);
        }
        self.input = chars.into_iter().collect();
        self.input_cursor = pos + s.chars().count();
    }

    /// Map mouse Y within the chat area to a transcript line index, if any.
    pub fn line_index_at_mouse(&self, col: u16, row: u16) -> Option<usize> {
        let (x, y, w, h) = self.chat_area?;
        if col < x || col >= x.saturating_add(w) || row < y || row >= y.saturating_add(h) {
            return None;
        }
        // Inner content starts at y+1 (border), height-2 usable rows.
        let inner_y = y.saturating_add(1);
        let inner_h = h.saturating_sub(2) as usize;
        if inner_h == 0 || row < inner_y {
            return None;
        }
        let row_in = (row - inner_y) as usize;
        if row_in >= inner_h {
            return None;
        }
        let total = self.lines.len();
        let max_scroll = self.max_chat_scroll();
        let scroll = self.chat_scroll.min(max_scroll);
        let end = total.saturating_sub(scroll);
        let start = end.saturating_sub(inner_h);
        let pad = inner_h.saturating_sub(end.saturating_sub(start));
        if row_in < pad {
            return None; // empty padding at top
        }
        let idx = start + (row_in - pad);
        if idx < total {
            Some(idx)
        } else {
            None
        }
    }

    pub fn point_in_rect(col: u16, row: u16, area: Option<(u16, u16, u16, u16)>) -> bool {
        let Some((x, y, w, h)) = area else {
            return false;
        };
        col >= x && col < x.saturating_add(w) && row >= y && row < y.saturating_add(h)
    }

    pub fn on_mouse(&mut self, ev: MouseEvent) {
        // Modals: ignore mouse for now (keyboard-first)
        if !matches!(self.view, View::Chat) {
            return;
        }
        let col = ev.column;
        let row = ev.row;
        match ev.kind {
            MouseEventKind::ScrollUp => {
                self.scroll_chat(3);
            }
            MouseEventKind::ScrollDown => {
                self.scroll_chat(-3);
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if Self::point_in_rect(col, row, self.input_area) {
                    self.focus_prompt();
                    return;
                }
                if let Some(idx) = self.line_index_at_mouse(col, row) {
                    self.pane_focus = PaneFocus::Scrollback;
                    self.selection = Some(LineSelection::single(idx));
                    self.stick_to_bottom = false;
                }
            }
            MouseEventKind::Drag(MouseButton::Left) => {
                if let Some(idx) = self.line_index_at_mouse(col, row) {
                    self.pane_focus = PaneFocus::Scrollback;
                    if let Some(sel) = self.selection.as_mut() {
                        sel.cursor = idx;
                    } else {
                        self.selection = Some(LineSelection::single(idx));
                    }
                    self.ensure_selection_visible();
                }
            }
            MouseEventKind::Up(MouseButton::Left) => {
                // no-op; selection already set
            }
            MouseEventKind::Down(MouseButton::Middle) => {
                // Linux PRIMARY paste into prompt when available (arboard has no PRIMARY on all platforms)
                // Fall through to CLIPBOARD paste as best-effort.
                if Self::point_in_rect(col, row, self.input_area)
                    || self.pane_focus == PaneFocus::Prompt
                {
                    self.paste_into_input();
                }
            }
            _ => {}
        }
    }

    pub fn on_paste_event(&mut self, text: String) {
        if !matches!(self.view, View::Chat) {
            return;
        }
        // Bracketed paste → input (secure or normal)
        let cleaned = text.replace('\r', "");
        self.input_insert_str(&cleaned);
        self.pane_focus = PaneFocus::Prompt;
    }

    pub fn transcript_lines(&self) -> Vec<TranscriptLine> {
        self.lines
            .iter()
            .map(|l| TranscriptLine {
                kind: match l.kind {
                    LineKind::User => "user",
                    LineKind::Assistant => "assistant",
                    LineKind::Thinking => "thinking",
                    LineKind::Tool => "tool",
                    LineKind::System => "system",
                    LineKind::Error => "error",
                }
                .into(),
                text: l.text.clone(),
            })
            .collect()
    }

    pub fn clear_for_new_session(&mut self, session_id: &str) {
        self.session_id = session_id.into();
        self.session_title = "New chat".into();
        self.lines = vec![ChatLine {
            kind: LineKind::System,
            text: format!(
                "New chat `{session_id}` · history auto-saves · /history to list · /resume <id>"
            ),
        }];
        self.pin_to_bottom();
        self.refresh_status();
    }

    /// True when the input bar should show a rotating help tooltip.
    pub fn show_idle_input_hint(&self) -> bool {
        matches!(self.view, View::Chat)
            && matches!(self.input_mode, InputMode::Normal)
            && self.input.is_empty()
            && !self.streaming
    }

    /// Advance idle tip rotation; call from the TUI frame loop.
    pub fn tick_idle_hint(&mut self) {
        self.idle_hint.tick(self.show_idle_input_hint());
    }

    pub fn refresh_status(&mut self) {
        // Grok Build–style: always show current / max (percent%) for context.
        let ctx = self
            .context
            .as_ref()
            .map(|c| format!("ctx {}", c.format_short()))
            .unwrap_or_else(|| "ctx — / — (—%)".into());
        let clouds = if self.config.oscar_config.tools.disabled_clouds.is_empty() {
            "all".into()
        } else {
            format!(
                "-{}",
                self.config.oscar_config.tools.disabled_clouds.join(",")
            )
        };
        let sid = if self.session_id.len() > 8 {
            format!("{}…", &self.session_id[..8])
        } else if self.session_id.is_empty() {
            "—".into()
        } else {
            self.session_id.clone()
        };
        self.status = format!(
            "oscar │ {} │ {}/{} │ {} │ chat:{} │ profiles:{} │ clouds:{} │ think:{} │ install:{}",
            self.config.mode,
            self.config.provider,
            self.config.model,
            ctx,
            sid,
            self.config.profile_count,
            clouds,
            if self.show_thinking { "on" } else { "off" },
            self.config.oscar_config.tools.install_binaries.as_str(),
        );
    }

    pub fn push_line(&mut self, kind: LineKind, text: impl Into<String>) {
        self.lines.push(ChatLine {
            kind,
            text: text.into(),
        });
        self.trim_transcript();
        // Streaming / new messages: stay pinned to bottom so text does not force the user to chase
        if self.stick_to_bottom {
            self.chat_scroll = 0;
        }
    }

    pub fn append_to_last(&mut self, kind: LineKind, text: &str) {
        if let Some(last) = self.lines.last_mut() {
            if last.kind == kind {
                last.text.push_str(text);
                if self.stick_to_bottom {
                    self.chat_scroll = 0;
                }
                return;
            }
        }
        self.push_line(kind, text);
    }

    pub fn open_settings(&mut self) {
        let pane = SettingsPane::open(
            self.config.oscar_config.clone(),
            self.config.tool_catalog.clone(),
        );
        self.view = View::Settings(pane);
    }

    /// Mark LLM provider as ready (after successful key paste / config reload).
    pub fn mark_provider_ready(&mut self, provider_id: &str, model: Option<&str>) {
        self.config.provider_ready = true;
        self.config.provider = provider_id.to_string();
        self.config.oscar_config.provider.id = provider_id.to_string();
        if let Some(m) = model {
            self.config.model = m.to_string();
            self.config.oscar_config.provider.model = Some(m.to_string());
        }
        self.refresh_status();
    }

    pub fn open_identities(&mut self) {
        let inv = load_quick_identities(&self.config.profiles_path);
        self.view = View::Identities(IdentitiesPane::open(inv));
        self.identity_detail = false;
        // Kick off live validation immediately
        self.pending_identity_probe = true;
        if let View::Identities(ref mut p) = self.view {
            p.probing = true;
            p.flash = Some("validating identities…".into());
        }
    }

    pub fn close_settings(&mut self, save: bool) {
        if let View::Settings(pane) = std::mem::replace(&mut self.view, View::Chat) {
            if save {
                self.apply_config(pane.config.clone());
                self.pending_config_save = Some(pane.config);
                self.push_line(
                    LineKind::System,
                    "Settings saved → ~/.config/oscar/config.toml (agent reloads tools/mode).",
                );
            } else {
                self.push_line(LineKind::System, "Settings closed without save.");
            }
        }
    }

    pub fn close_identities(&mut self) {
        if let View::Identities(pane) = std::mem::replace(&mut self.view, View::Chat) {
            self.push_line(
                LineKind::System,
                format!("Identities closed — {}", pane.inventory.summary_line()),
            );
        }
        self.identity_detail = false;
    }

    pub fn apply_identity_inventory(&mut self, inv: IdentityInventory) {
        if let View::Identities(pane) = &mut self.view {
            pane.apply_inventory(inv);
        }
    }

    fn apply_config(&mut self, cfg: OscarConfig) {
        self.config.oscar_config = cfg.clone();
        self.config.mode = cfg.mode;
        self.config.provider = cfg.provider.id.clone();
        if let Some(m) = cfg.provider.model.clone() {
            self.config.model = m;
        }
        self.show_thinking = cfg.ui.show_thinking || cfg.thinking.is_on();
        self.config.show_thinking = self.show_thinking;
        self.config.provider_ready = oscar_identity::load_provider_api_key(&cfg.provider.id)
            .ok()
            .flatten()
            .map(|k| !k.is_empty())
            .unwrap_or(false);
        self.refresh_status();
    }

    pub fn handle_agent_event(&mut self, ev: AgentEvent) {
        match ev {
            AgentEvent::ContentDelta { text } => {
                if text.contains("[provider ready") {
                    // Host stored LLM key and built agent — allow chat.
                    let pid = self.config.provider.clone();
                    self.mark_provider_ready(&pid, None);
                    self.push_line(LineKind::System, text.trim().to_string());
                    return;
                }
                self.streaming = true;
                // Close thinking block when answer starts
                if self.thinking_open {
                    self.finish_thinking_header();
                }
                self.activity = AgentActivity::Answering;
                self.append_to_last(LineKind::Assistant, &text);
            }
            AgentEvent::ThinkingDelta { text } => {
                self.streaming = true;
                self.activity = AgentActivity::Thinking;
                self.thinking_chars = self.thinking_chars.saturating_add(text.chars().count());
                // Always show a thinking *header* (Grok Build); body when show_thinking is on.
                if !self.thinking_open {
                    self.thinking_open = true;
                    self.push_line(
                        LineKind::Thinking,
                        format!("{} thinking…", self.spinner_frame()),
                    );
                } else {
                    // Keep header live with spinner + char count
                    self.update_thinking_header_live();
                }
                if self.show_thinking && !text.is_empty() {
                    // Body lines under the header (dim in draw)
                    if self
                        .lines
                        .last()
                        .map(|l| l.kind == LineKind::Thinking && l.text.starts_with('│'))
                        .unwrap_or(false)
                    {
                        self.append_to_last(LineKind::Thinking, &text);
                    } else {
                        // New body line; collapse excessive whitespace noise
                        let t = text.replace('\n', " ");
                        self.push_line(LineKind::Thinking, format!("│ {t}"));
                    }
                }
            }
            AgentEvent::ThinkingDone { chars } => {
                self.thinking_chars = chars.max(self.thinking_chars);
                self.finish_thinking_header();
                if !matches!(self.activity, AgentActivity::Tool { .. }) {
                    self.activity = if self.streaming {
                        AgentActivity::Answering
                    } else {
                        AgentActivity::Idle
                    };
                }
            }
            AgentEvent::ToolSearch { query, hits } => {
                if self.thinking_open {
                    self.finish_thinking_header();
                }
                self.activity = AgentActivity::Tool {
                    id: "tools_search".into(),
                };
                // Grok Build–style tool card: name, then result
                self.push_line(LineKind::Tool, String::from("⚙ tools_search"));
                self.push_line(
                    LineKind::Tool,
                    format!("  query: \"{}\"", truncate_str(&query, 80)),
                );
                self.push_line(
                    LineKind::Tool,
                    format!("✓ tools_search · {hits} tool(s) matched"),
                );
                self.activity = AgentActivity::Answering;
            }
            AgentEvent::ToolStart {
                tool_id,
                args_redacted,
            } => {
                if self.thinking_open {
                    self.finish_thinking_header();
                }
                self.streaming = true;
                self.activity = AgentActivity::Tool {
                    id: tool_id.clone(),
                };
                // Running card (Grok: tool name + redacted args)
                self.push_line(LineKind::Tool, format!("⚙ {tool_id}"));
                let args_s = compact_json(&args_redacted);
                if args_s != "{}" && args_s != "null" {
                    self.push_line(
                        LineKind::Tool,
                        format!("  args: {}", truncate_str(&args_s, 120)),
                    );
                }
            }
            AgentEvent::ToolEnd { tool_id, summary } => {
                let ok = !summary.to_ascii_lowercase().contains("error")
                    && !summary.to_ascii_lowercase().contains("failed")
                    && !summary.starts_with("missing_")
                    && !summary.starts_with("unknown tool")
                    && !summary.starts_with("binary_gate");
                let mark = if ok { "✓" } else { "✗" };
                self.push_line(
                    LineKind::Tool,
                    format!(
                        "{mark} {tool_id} · {}",
                        truncate_str(&summary, 140)
                    ),
                );
                self.activity = AgentActivity::Answering;
            }
            AgentEvent::ContextUsage(snap) => {
                self.context = Some(snap);
                self.refresh_status();
            }
            AgentEvent::CompactionStarted { reason } => {
                self.push_line(
                    LineKind::System,
                    format!("Compacting session ({reason:?})…"),
                );
            }
            AgentEvent::CompactionFinished { before, after } => {
                self.push_line(
                    LineKind::System,
                    format!(
                        "Compacted context: {} → {}  (was {:.0}% → now {:.0}% of max {})",
                        before.format_short(),
                        after.format_short(),
                        before.percent,
                        after.percent,
                        after.context_window
                    ),
                );
                self.context = Some(after);
                self.refresh_status();
            }
            AgentEvent::AuthRequired(auth) => {
                let reauth = if auth.reauth {
                    " [EXPIRED — re-auth]"
                } else {
                    " [missing]"
                };
                self.push_line(
                    LineKind::System,
                    format!("Credentials needed{reauth}: {}", auth.reason),
                );
                if let Some(g) = &auth.guidance {
                    self.push_line(LineKind::System, format!("guidance: {g}"));
                }
                if !auth.hint_commands.is_empty() {
                    self.push_line(
                        LineKind::System,
                        format!("try: {}", auth.hint_commands.join(" | ")),
                    );
                }
                self.push_line(
                    LineKind::System,
                    "After auth, oscar auto-retries the paused tool. Secrets go to OS keychain only — the agent never sees pasted values.",
                );
                if auth.kinds.is_empty() {
                    self.push_line(
                        LineKind::System,
                        "No secret fields to paste — run the hint command (e.g. aws sso login), then type `retry`.",
                    );
                } else {
                    let fields: Vec<_> = auth.kinds.iter().map(|k| format!("{k:?}")).collect();
                    self.push_line(
                        LineKind::System,
                        format!(
                            "SECURE bar (masked): paste fields in order [{}] for profile `{}` — not in chat.",
                            fields.join(" → "),
                            auth.profile_hint.as_deref().unwrap_or("?")
                        ),
                    );
                    self.input_mode = InputMode::secure(auth);
                    self.input.clear();
                }
            }
            AgentEvent::AuthPendingRetry { tool_id, auth, .. } => {
                self.push_line(
                    LineKind::System,
                    format!(
                        "Paused tool `{}` until credentials ready (reauth={})",
                        tool_id, auth.reauth
                    ),
                );
                self.streaming = false;
            }
            AgentEvent::AuthResumed { tool_id, profile_id } => {
                self.push_line(
                    LineKind::System,
                    format!(
                        "Resuming `{}`{}",
                        tool_id,
                        profile_id
                            .as_ref()
                            .map(|p| format!(" (profile {p})"))
                            .unwrap_or_default()
                    ),
                );
                self.streaming = true;
            }
            AgentEvent::ModeDenied { tool_id, reason } => {
                self.push_line(
                    LineKind::Error,
                    format!("mode denied for {tool_id}: {reason}"),
                );
            }
            AgentEvent::InstallApprovalRequired {
                packages,
                commands,
                reason,
                install_all,
            } => {
                let intent = if install_all {
                    "install-all policy"
                } else {
                    "ask-admin policy"
                };
                self.push_line(
                    LineKind::System,
                    format!("Admin install approval needed ({intent}): {reason}"),
                );
                if !packages.is_empty() {
                    self.push_line(
                        LineKind::System,
                        format!("packages: {}", packages.join(", ")),
                    );
                }
                for c in &commands {
                    self.push_line(LineKind::System, format!("  $ {c}"));
                }
                self.push_line(
                    LineKind::System,
                    "Type `approve install` to run elevated install, or `deny install` to skip.",
                );
                self.push_line(
                    LineKind::System,
                    "Or open /settings → Install binaries.",
                );
                self.streaming = false;
            }
            AgentEvent::InstallCompleted { ok, summary } => {
                self.push_line(
                    if ok {
                        LineKind::System
                    } else {
                        LineKind::Error
                    },
                    format!(
                        "Install {}: {}",
                        if ok { "completed" } else { "failed" },
                        summary
                    ),
                );
            }
            AgentEvent::Error { message } => {
                let needs_provider = message.to_ascii_lowercase().contains("no llm provider")
                    || message.to_ascii_lowercase().contains("provider not ready")
                    || message.to_ascii_lowercase().contains("no api key for provider")
                    || message.to_ascii_lowercase().contains("provider-key");
                self.push_line(LineKind::Error, message);
                if needs_provider && !self.config.provider_ready {
                    self.open_provider_setup(
                        "LLM provider missing or not ready — open Provider settings to select and paste a key.",
                    );
                }
            }
            AgentEvent::Done { .. } => {
                if self.thinking_open {
                    self.finish_thinking_header();
                }
                self.streaming = false;
                self.activity = AgentActivity::Idle;
                self.pending_session_save = true;
                // End of turn: snap back to newest so load/stream never leaves user mid-history
                self.pin_to_bottom();
            }
        }
    }

    fn update_thinking_header_live(&mut self) {
        let sp = self.spinner_frame();
        let n = self.thinking_chars;
        if let Some(line) = self.lines.iter_mut().rev().find(|l| {
            l.kind == LineKind::Thinking
                && (l.text.contains("thinking") && !l.text.starts_with('│'))
        }) {
            line.text = format!("{sp} thinking… ({n} chars)");
        }
    }

    fn finish_thinking_header(&mut self) {
        if !self.thinking_open {
            return;
        }
        if let Some(line) = self.lines.iter_mut().rev().find(|l| {
            l.kind == LineKind::Thinking
                && (l.text.contains("thinking") && !l.text.starts_with('│'))
        }) {
            line.text = format!("✧ thinking · done ({} chars)", self.thinking_chars);
        } else if self.thinking_chars > 0 {
            // Header missing (e.g. show_thinking off and we never opened body) — still record
            self.push_line(
                LineKind::Thinking,
                format!("✧ thinking · done ({} chars)", self.thinking_chars),
            );
        }
        self.thinking_open = false;
        self.thinking_chars = 0;
    }

    pub fn on_key(&mut self, key: crossterm::event::KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Overlays capture keys first
        if matches!(self.view, View::Settings(_)) {
            self.on_settings_key(key);
            return;
        }
        if matches!(self.view, View::Provider(_)) {
            self.on_provider_key(key);
            return;
        }
        if matches!(self.view, View::Identities(_)) {
            self.on_identities_key(key);
            return;
        }

        // Cancel works even when stuck: Esc / Ctrl+C while streaming (or fake-streaming).
        if self.streaming
            && (key.code == KeyCode::Esc
                || (key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('c')))
        {
            self.cancel_requested = true;
            self.streaming = false;
            self.activity = AgentActivity::Idle;
            self.push_line(LineKind::System, "Cancel requested — stopping generation…");
            return;
        }
        // Block almost all chat interaction until a provider is ready (except setup shortcuts).
        if !self.config.provider_ready
            && matches!(self.view, View::Chat)
            && matches!(self.input_mode, InputMode::Normal)
        {
            let is_setup = matches!(
                key.code,
                KeyCode::Char(',') | KeyCode::Char('i')
            ) && key.modifiers.contains(KeyModifiers::CONTROL);
            let is_help_or_quit = matches!(key.code, KeyCode::Esc)
                || (key.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(key.code, KeyCode::Char('c')));
            // Allow typing so user can type /provider; still intercept plain Enter without /.
            // Provider setup already auto-opened; keep Esc from quitting immediately if they need setup.
            if key.code == KeyCode::Esc && !is_help_or_quit {
                self.open_provider_setup(
                    "Chat is disabled until an LLM provider is ready. Use Provider setup.",
                );
                return;
            }
            let _ = is_setup;
        }

        // Global Ctrl chords available in chat (prompt-oriented unless noted).
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('v') | KeyCode::Char('V') => {
                    // Paste into composer (Grok Build Ctrl+V)
                    self.paste_into_input();
                    return;
                }
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    // Copy selection / last assistant (works from either pane)
                    self.copy_selection();
                    return;
                }
                KeyCode::Char('u') | KeyCode::Char('U')
                    if self.pane_focus == PaneFocus::Prompt
                        || matches!(self.input_mode, InputMode::Secure { .. }) =>
                {
                    self.input_clear();
                    return;
                }
                KeyCode::Char('a') | KeyCode::Char('A')
                    if self.pane_focus == PaneFocus::Prompt
                        || matches!(self.input_mode, InputMode::Secure { .. }) =>
                {
                    self.input_home();
                    return;
                }
                KeyCode::Char('e') | KeyCode::Char('E')
                    if self.pane_focus == PaneFocus::Prompt
                        || matches!(self.input_mode, InputMode::Secure { .. }) =>
                {
                    self.input_end();
                    return;
                }
                _ => {}
            }
        }

        // Tab toggles controllable panes (scrollback ↔ prompt), Grok Build–style.
        if matches!(self.view, View::Chat)
            && matches!(self.input_mode, InputMode::Normal)
            && key.code == KeyCode::Tab
            && !key.modifiers.contains(KeyModifiers::SHIFT)
        {
            self.toggle_pane_focus();
            return;
        }

        // Scrollback-focused navigation: select / highlight / copy (not typing).
        if matches!(self.view, View::Chat)
            && matches!(self.input_mode, InputMode::Normal)
            && self.pane_focus == PaneFocus::Scrollback
        {
            let shift = key.modifiers.contains(KeyModifiers::SHIFT);
            match key.code {
                KeyCode::Esc | KeyCode::Char(' ') => {
                    // Esc/Space return to prompt (Esc does not quit while scrollback focused)
                    self.focus_prompt();
                    return;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.move_selection(-1, shift);
                    return;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.move_selection(1, shift);
                    return;
                }
                KeyCode::PageUp => {
                    self.move_selection(-12, shift);
                    return;
                }
                KeyCode::PageDown => {
                    self.move_selection(12, shift);
                    return;
                }
                KeyCode::Home => {
                    if !self.lines.is_empty() {
                        let idx = 0;
                        if shift {
                            if let Some(sel) = self.selection.as_mut() {
                                sel.cursor = idx;
                            } else {
                                self.selection = Some(LineSelection::single(idx));
                            }
                        } else {
                            self.selection = Some(LineSelection::single(idx));
                        }
                        self.ensure_selection_visible();
                    }
                    return;
                }
                KeyCode::End => {
                    if !self.lines.is_empty() {
                        let idx = self.lines.len() - 1;
                        if shift {
                            if let Some(sel) = self.selection.as_mut() {
                                sel.cursor = idx;
                            } else {
                                self.selection = Some(LineSelection::single(idx));
                            }
                        } else {
                            self.selection = Some(LineSelection::single(idx));
                        }
                        self.ensure_selection_visible();
                    }
                    return;
                }
                KeyCode::Char('y') | KeyCode::Char('Y')
                    if !key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    self.copy_selection();
                    return;
                }
                KeyCode::Char('c')
                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    // Copy when scrollback focused; don't quit
                    self.copy_selection();
                    return;
                }
                KeyCode::Enter => {
                    // Copy selection as the primary "action" on Enter in scrollback
                    self.copy_selection();
                    return;
                }
                // Any printable character auto-focuses the prompt and types (Grok simple mode)
                KeyCode::Char(c)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && !key.modifiers.contains(KeyModifiers::ALT) =>
                {
                    self.focus_prompt();
                    self.input_insert_char(c);
                    return;
                }
                KeyCode::Backspace => {
                    self.focus_prompt();
                    self.input_backspace();
                    return;
                }
                _ => {}
            }
        }

        match &mut self.input_mode {
            InputMode::Secure {
                auth,
                kind_index,
                buffer: _,
            } => match key.code {
                KeyCode::Esc => {
                    self.input_mode = InputMode::Normal;
                    self.input_cursor = 0;
                    self.push_line(LineKind::System, "Credential entry cancelled.");
                }
                KeyCode::Backspace => {
                    self.input_backspace();
                }
                KeyCode::Left => {
                    if self.input_cursor > 0 {
                        self.input_cursor -= 1;
                    }
                }
                KeyCode::Right => {
                    self.input_cursor = self.input_cursor.saturating_add(1);
                    self.clamp_cursor();
                }
                KeyCode::Home => self.input_home(),
                KeyCode::End => self.input_end(),
                KeyCode::Enter => {
                    let empty = match &self.input_mode {
                        InputMode::Secure { buffer, .. } => buffer.is_empty(),
                        _ => true,
                    };
                    if empty {
                        return;
                    }
                    // re-borrow for mutation after empty check
                    let (kind, secret, auth_clone, done) = {
                        let InputMode::Secure {
                            auth,
                            kind_index,
                            buffer,
                        } = &mut self.input_mode
                        else {
                            return;
                        };
                        let kind = auth.kinds.get(*kind_index).copied();
                        let Some(kind) = kind else { return };
                        let secret = std::mem::take(buffer);
                        let auth_clone = auth.clone();
                        let next = *kind_index + 1;
                        let done = next >= auth.kinds.len();
                        if !done {
                            *kind_index = next;
                        }
                        (kind, secret, auth_clone, done)
                    };
                    self.pending_secret = Some((auth_clone, kind, secret));
                    self.input_cursor = 0;
                    if done {
                        self.input_mode = InputMode::Normal;
                    }
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.input_insert_char(c);
                }
                _ => {
                    let _ = auth;
                    let _ = kind_index;
                }
            },
            InputMode::Normal => match key.code {
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.should_quit = true;
                }
                KeyCode::Char(',') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.open_settings();
                }
                KeyCode::Char('i') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.open_identities();
                }
                KeyCode::Esc => {
                    // Double-purpose: if selection active, clear it; else quit
                    if self.selection.is_some() {
                        self.selection = None;
                        self.copy_flash = Some("Selection cleared".into());
                        return;
                    }
                    self.should_quit = true;
                }
                KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.show_thinking = !self.show_thinking;
                    self.config.oscar_config.ui.show_thinking = self.show_thinking;
                    self.refresh_status();
                }
                // Chat scroll while prompt focused (Grok: PgUp/PgDn scroll without changing focus)
                KeyCode::PageUp => {
                    self.scroll_chat(12);
                }
                KeyCode::PageDown => {
                    self.scroll_chat(-12);
                }
                KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.scroll_chat(3);
                }
                KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.scroll_chat(-3);
                }
                // Up/Down with empty input: jump into scrollback selection (discoverable)
                KeyCode::Up if self.input.is_empty() && !key.modifiers.contains(KeyModifiers::SHIFT) => {
                    self.focus_scrollback();
                    self.move_selection(-1, false);
                }
                KeyCode::Down if self.input.is_empty() && !key.modifiers.contains(KeyModifiers::SHIFT) => {
                    self.focus_scrollback();
                    self.move_selection(1, false);
                }
                KeyCode::Home if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    // Furthest allowed back (cutoff), not infinite history
                    self.chat_scroll = self.max_chat_scroll();
                    self.stick_to_bottom = self.chat_scroll == 0;
                }
                KeyCode::Home => self.input_home(),
                KeyCode::End if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.pin_to_bottom();
                }
                KeyCode::End => {
                    self.input_end();
                }
                KeyCode::Left => {
                    if self.input_cursor > 0 {
                        self.input_cursor -= 1;
                    }
                }
                KeyCode::Right => {
                    self.input_cursor = self.input_cursor.saturating_add(1);
                    self.clamp_cursor();
                }
                KeyCode::Enter => {
                    let line = self.input.trim().to_string();
                    if line.is_empty() || self.streaming {
                        return;
                    }
                    if !self.config.provider_ready
                        && !line.starts_with('/')
                        && line != "/quit"
                        && line != "/exit"
                    {
                        // Chat needs an LLM — open provider setup instead of failing later.
                        self.open_provider_setup(
                            "LLM provider not ready — set one up before chatting.",
                        );
                        return;
                    }
                    self.input.clear();
                    self.input_cursor = 0;
                    // Next tip after a send (fresh guidance while waiting / idle again)
                    self.idle_hint.next();
                    if line == "/quit" || line == "/exit" {
                        self.should_quit = true;
                        return;
                    }
                    if matches!(
                        line.as_str(),
                        "/settings" | "/config" | "/preferences" | "/prefs"
                    ) {
                        self.open_settings();
                        return;
                    }
                    if matches!(
                        line.as_str(),
                        "/provider" | "/providers" | "/llm" | "/api-key" | "/apikey"
                    ) {
                        self.open_provider_setup("Provider / API key setup");
                        return;
                    }
                    if matches!(
                        line.as_str(),
                        "/identities" | "/identity" | "/access" | "/whoami"
                    ) {
                        self.open_identities();
                        return;
                    }
                    if line == "/help" {
                        self.push_line(
                            LineKind::System,
                            "/settings · /provider · /identities · /skills · /mcp · /thinking · /context · /compact · /history · /new · /resume · /copy · /quit",
                        );
                        self.push_line(
                            LineKind::System,
                            "Panes: Tab = chat↔input · ↑↓ select lines · Shift+↑↓ extend · y/Enter/Ctrl+Y copy · Ctrl+V paste",
                        );
                        self.push_line(
                            LineKind::System,
                            "Input: Ctrl+A start · Ctrl+E end · Ctrl+U clear · Settings Ctrl+, · Identities Ctrl+I · mouse click/drag select",
                        );
                        return;
                    }
                    // /copy [n] — Grok Build–style copy last (or Nth) assistant reply
                    if line == "/copy" {
                        self.copy_nth_assistant(1);
                        return;
                    }
                    if let Some(rest) = line.strip_prefix("/copy ") {
                        let rest = rest.trim();
                        if rest.is_empty() {
                            self.copy_nth_assistant(1);
                            return;
                        }
                        if let Ok(n) = rest.parse::<usize>() {
                            self.copy_nth_assistant(n);
                            return;
                        }
                        // /copy path — write selection/last assistant to file
                        if let Some(text) = self.selection_text() {
                            match std::fs::write(rest, &text) {
                                Ok(()) => self.push_line(
                                    LineKind::System,
                                    format!("Wrote {} bytes → {rest}", text.len()),
                                ),
                                Err(e) => self.push_line(
                                    LineKind::Error,
                                    format!("Write failed: {e}"),
                                ),
                            }
                        } else {
                            self.push_line(LineKind::System, "Nothing to copy.");
                        }
                        return;
                    }
                    if line == "/new" {
                        self.push_line(LineKind::System, "Starting new chat…");
                        self.pending_user = Some("/new".into());
                        return;
                    }
                    if line == "/history"
                        || line == "/sessions"
                        || line.starts_with("/resume ")
                        || line.starts_with("/session ")
                        || line.starts_with("/history ")
                    {
                        self.push_line(LineKind::User, line.clone());
                        self.pending_user = Some(line);
                        return;
                    }
                    // /mcp goes to host (list/enable/disable)
                    if line == "/mcp" || line.starts_with("/mcp ") {
                        self.push_line(LineKind::User, line.clone());
                        self.pending_user = Some(line);
                        return;
                    }
                    if line == "/thinking"
                        || line.starts_with("/thinking ")
                        || line == "/context"
                        || line == "/compact"
                        || line == "/mode"
                        || line.starts_with("/settings ")
                    {
                        self.push_line(LineKind::User, line.clone());
                        self.pending_user = Some(line);
                        return;
                    }
                    // /skill and /skills go to host
                    if line == "/skills"
                        || line.starts_with("/skill ")
                        || line.starts_with("/skills ")
                    {
                        self.push_line(LineKind::User, line.clone());
                        self.pending_user = Some(line);
                        return;
                    }
                    self.push_line(LineKind::User, line.clone());
                    self.pending_user = Some(line);
                }
                KeyCode::Backspace => {
                    self.input_backspace();
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.input_insert_char(c);
                }
                _ => {}
            },
        }
    }

    fn on_settings_key(&mut self, key: crossterm::event::KeyEvent) {
        use crate::settings::SettingsFocus;

        let View::Settings(ref mut pane) = self.view else {
            return;
        };

        match key.code {
            KeyCode::Esc => {
                // Drill out of items first; second Esc (or Esc on categories) closes.
                if pane.drill_out() {
                    self.close_settings(true);
                }
            }
            KeyCode::Char('q') if key.modifiers.is_empty() => {
                self.close_settings(true);
            }
            KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                // explicit save keep open
                let cfg = pane.config.clone();
                pane.dirty = false;
                pane.flash = Some("saved".into());
                self.apply_config(cfg.clone());
                self.pending_config_save = Some(cfg);
            }
            // ↑↓ — move within focused column (raw config scrolls TOML)
            KeyCode::Up | KeyCode::Char('k') => match pane.focus {
                SettingsFocus::Categories => pane.move_category(-1),
                SettingsFocus::Items
                    if pane.category() == crate::settings::SettingsCategory::RawConfig =>
                {
                    pane.scroll_raw(-1, 20);
                }
                SettingsFocus::Items => pane.move_item(-1),
            },
            KeyCode::Down | KeyCode::Char('j') => match pane.focus {
                SettingsFocus::Categories => pane.move_category(1),
                SettingsFocus::Items
                    if pane.category() == crate::settings::SettingsCategory::RawConfig =>
                {
                    pane.scroll_raw(1, 20);
                }
                SettingsFocus::Items => pane.move_item(1),
            },
            // → drill into menu · ← drill out
            KeyCode::Right | KeyCode::Char('l') => {
                if pane.focus == SettingsFocus::Categories {
                    // Provider category opens dedicated provider UI
                    if pane.category() == crate::settings::SettingsCategory::Provider {
                        self.open_provider_setup("Provider setup");
                        return;
                    }
                    pane.drill_in();
                } else if pane.category() == crate::settings::SettingsCategory::RawConfig {
                    // Already in raw viewer — no enum cycle
                } else {
                    // In items: Right cycles enums / toggles forward
                    pane.activate();
                    self.handle_settings_action();
                    return;
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if pane.focus == SettingsFocus::Items {
                    let _ = pane.drill_out();
                } else {
                    // On categories: Left also steps previous category
                    pane.move_category(-1);
                }
            }
            KeyCode::Tab => {
                if pane.focus == SettingsFocus::Categories {
                    pane.drill_in();
                } else {
                    let _ = pane.drill_out();
                }
            }
            KeyCode::BackTab => {
                let _ = pane.drill_out();
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                if pane.category() == crate::settings::SettingsCategory::RawConfig
                    && pane.focus == SettingsFocus::Categories
                {
                    pane.drill_in();
                    return;
                }
                if pane.category() == crate::settings::SettingsCategory::RawConfig {
                    return; // no toggles in raw viewer
                }
                pane.activate();
                self.handle_settings_action();
                return;
            }
            KeyCode::Char('[') => {
                if pane.focus == SettingsFocus::Items
                    && pane.category() != crate::settings::SettingsCategory::RawConfig
                {
                    pane.activate_back();
                }
            }
            KeyCode::Char(']') => {
                if pane.focus == SettingsFocus::Items
                    && pane.category() != crate::settings::SettingsCategory::RawConfig
                {
                    pane.activate();
                    self.handle_settings_action();
                    return;
                }
            }
            KeyCode::PageUp => {
                match pane.focus {
                    SettingsFocus::Categories => {
                        for _ in 0..10 {
                            pane.move_category(-1);
                        }
                    }
                    SettingsFocus::Items
                        if pane.category() == crate::settings::SettingsCategory::RawConfig =>
                    {
                        pane.scroll_raw(-10, 20);
                    }
                    SettingsFocus::Items => {
                        for _ in 0..10 {
                            pane.move_item(-1);
                        }
                    }
                }
            }
            KeyCode::PageDown => {
                match pane.focus {
                    SettingsFocus::Categories => {
                        for _ in 0..10 {
                            pane.move_category(1);
                        }
                    }
                    SettingsFocus::Items
                        if pane.category() == crate::settings::SettingsCategory::RawConfig =>
                    {
                        pane.scroll_raw(10, 20);
                    }
                    SettingsFocus::Items => {
                        for _ in 0..10 {
                            pane.move_item(1);
                        }
                    }
                }
            }
            KeyCode::Home => {
                if pane.focus == SettingsFocus::Items {
                    if pane.category() == crate::settings::SettingsCategory::RawConfig {
                        pane.scroll_raw_home();
                    } else {
                        pane.item_idx = 0;
                    }
                } else {
                    pane.category_idx = 0;
                    pane.raw_scroll = 0;
                }
            }
            KeyCode::End => {
                if pane.focus == SettingsFocus::Items {
                    if pane.category() == crate::settings::SettingsCategory::RawConfig {
                        pane.scroll_raw_end(20);
                    } else {
                        let n = pane.items().len();
                        if n > 0 {
                            pane.item_idx = n - 1;
                        }
                    }
                } else {
                    pane.category_idx = crate::settings::SettingsCategory::ALL.len() - 1;
                    pane.raw_scroll = 0;
                }
            }
            // number keys jump categories 1-9
            KeyCode::Char(c @ '1'..='9') => {
                let idx = (c as u8 - b'1') as usize;
                if idx < crate::settings::SettingsCategory::ALL.len() {
                    pane.category_idx = idx;
                    pane.item_idx = 0;
                    pane.item_scroll = 0;
                    pane.raw_scroll = 0;
                    pane.focus = SettingsFocus::Categories;
                    pane.flash = Some(pane.category().hint().into());
                }
            }
            KeyCode::Char('i') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                // Jump from settings to identities panel
                self.view = View::Chat;
                self.open_identities();
                return;
            }
            // y / Ctrl+Y — copy raw TOML when viewing Raw config (Grok-style copy)
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if pane.category() == crate::settings::SettingsCategory::RawConfig {
                    let raw = pane.raw_toml();
                    let outcome = crate::clipboard::copy_text(&raw);
                    pane.flash = Some(outcome.message);
                }
            }
            _ => {}
        }
    }

    /// Handle one-shot settings actions (legacy settings provider category).
    fn handle_settings_action(&mut self) {
        use crate::settings::{provider_auth_url, SettingsAction};
        let action = match &mut self.view {
            View::Settings(pane) => pane.take_action(),
            _ => None,
        };
        match action {
            Some(SettingsAction::PasteProviderApiKey { provider_id }) => {
                self.close_settings(true);
                self.begin_provider_key_paste(provider_id);
            }
            Some(SettingsAction::SignInProvider { provider_id }) => {
                let url = provider_auth_url(&provider_id);
                let opened = open_browser_url(url);
                self.close_settings(true);
                self.push_line(
                    LineKind::System,
                    if opened {
                        format!(
                            "Opened browser for `{provider_id}` ({url}). Copy an API key, then paste in the secure bar."
                        )
                    } else {
                        format!(
                            "Open {url} for `{provider_id}`, copy an API key, then paste in the secure bar."
                        )
                    },
                );
                self.begin_provider_key_paste(provider_id);
            }
            None => {}
        }
    }

    fn on_provider_key(&mut self, key: crossterm::event::KeyEvent) {
        use crate::provider_pane::ProviderFocus;

        // Editing model / URL captures keys first
        let editing = matches!(&self.view, View::Provider(p) if p.edit.is_some());
        if editing {
            match key.code {
                KeyCode::Esc => {
                    if let View::Provider(p) = &mut self.view {
                        p.edit = None;
                        p.flash = Some("edit cancelled".into());
                    }
                }
                KeyCode::Enter => {
                    if let View::Provider(p) = &mut self.view {
                        p.activate(); // commits edit
                    }
                    self.dispatch_provider_pending();
                }
                KeyCode::Backspace => {
                    if let View::Provider(p) = &mut self.view {
                        p.edit_backspace();
                    }
                }
                KeyCode::Left => {
                    if let View::Provider(p) = &mut self.view {
                        p.edit_left();
                    }
                }
                KeyCode::Right => {
                    if let View::Provider(p) = &mut self.view {
                        p.edit_right();
                    }
                }
                KeyCode::Home => {
                    if let View::Provider(p) = &mut self.view {
                        p.edit_home();
                    }
                }
                KeyCode::End => {
                    if let View::Provider(p) = &mut self.view {
                        p.edit_end();
                    }
                }
                KeyCode::Char('u') | KeyCode::Char('U')
                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    if let View::Provider(p) = &mut self.view {
                        p.edit_clear();
                    }
                }
                KeyCode::Char('a') | KeyCode::Char('A')
                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    if let View::Provider(p) = &mut self.view {
                        p.edit_home();
                    }
                }
                KeyCode::Char('e') | KeyCode::Char('E')
                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    if let View::Provider(p) = &mut self.view {
                        p.edit_end();
                    }
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if let View::Provider(p) = &mut self.view {
                        p.edit_insert(c);
                    }
                }
                _ => {}
            }
            return;
        }

        let View::Provider(ref mut pane) = self.view else {
            return;
        };

        match key.code {
            KeyCode::Esc => {
                if pane.drill_out() {
                    self.close_provider_pane(true);
                }
            }
            KeyCode::Char('q') if key.modifiers.is_empty() => {
                self.close_provider_pane(true);
            }
            KeyCode::Up | KeyCode::Char('k') => match pane.focus {
                ProviderFocus::List => pane.move_list(-1),
                ProviderFocus::Actions => pane.move_action(-1),
            },
            KeyCode::Down | KeyCode::Char('j') => match pane.focus {
                ProviderFocus::List => pane.move_list(1),
                ProviderFocus::Actions => pane.move_action(1),
            },
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Tab => {
                if pane.focus == ProviderFocus::List {
                    pane.drill_in();
                } else {
                    pane.activate();
                    self.dispatch_provider_pending();
                    return;
                }
            }
            KeyCode::Left | KeyCode::Char('h') | KeyCode::BackTab => {
                let _ = pane.drill_out();
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                pane.activate();
                self.dispatch_provider_pending();
            }
            KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let cfg = pane.config.clone();
                pane.dirty = false;
                pane.flash = Some("saved".into());
                self.apply_config(cfg.clone());
                self.pending_config_save = Some(cfg);
            }
            _ => {}
        }
    }

    fn dispatch_provider_pending(&mut self) {
        let pending = match &mut self.view {
            View::Provider(p) => p.take_pending(),
            _ => None,
        };
        let cfg_snapshot = match &self.view {
            View::Provider(p) => Some(p.config.clone()),
            _ => None,
        };
        match pending {
            Some(ProviderPaneAction::PasteApiKey { provider_id }) => {
                if let Some(cfg) = cfg_snapshot {
                    self.apply_config(cfg.clone());
                    self.pending_config_save = Some(cfg);
                }
                self.view = View::Chat;
                self.begin_provider_key_paste(provider_id);
            }
            Some(ProviderPaneAction::OpenBrowser { url, label }) => {
                let opened = open_browser_url(&url);
                self.push_line(
                    LineKind::System,
                    if opened {
                        format!("Opened browser: {label} — {url}")
                    } else {
                        format!("Open in browser: {url} ({label})")
                    },
                );
            }
            Some(ProviderPaneAction::ConfigChanged) => {
                if let Some(cfg) = cfg_snapshot {
                    self.apply_config(cfg.clone());
                    self.pending_config_save = Some(cfg);
                }
            }
            Some(ProviderPaneAction::Close) => {
                self.close_provider_pane(true);
            }
            None => {}
        }
    }

    fn on_identities_key(&mut self, key: crossterm::event::KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                if self.identity_detail {
                    self.identity_detail = false;
                } else {
                    self.close_identities();
                }
            }
            KeyCode::Char('r') | KeyCode::F(5) => {
                self.pending_identity_probe = true;
                if let View::Identities(p) = &mut self.view {
                    p.probing = true;
                    p.flash = Some("re-validating…".into());
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if let View::Identities(p) = &mut self.view {
                    p.filter = filter_prev(p.filter);
                    p.selected = 0;
                    p.flash = Some(format!("filter: {}", p.filter.label()));
                }
            }
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Tab => {
                if let View::Identities(p) = &mut self.view {
                    p.filter = p.filter.next();
                    p.selected = 0;
                    p.flash = Some(format!("filter: {}", p.filter.label()));
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let View::Identities(p) = &mut self.view {
                    p.move_sel(-1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let View::Identities(p) = &mut self.view {
                    p.move_sel(1);
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.identity_detail = !self.identity_detail;
            }
            _ => {}
        }
    }
}

fn filter_prev(f: crate::identities::FilterCloud) -> crate::identities::FilterCloud {
    use crate::identities::FilterCloud::*;
    match f {
        All => Llm,
        Aws => All,
        Gcp => Aws,
        Azure => Gcp,
        K8s => Azure,
        Llm => K8s,
    }
}

fn load_quick_identities(profiles_path: &std::path::Path) -> IdentityInventory {
    match ProfileStore::load_path(profiles_path) {
        Ok(store) => build_identity_inventory_quick(&store),
        Err(_) => IdentityInventory::default(),
    }
}

fn compact_json(v: &serde_json::Value) -> String {
    let s = v.to_string();
    truncate_str(&s, 100)
}

fn truncate_str(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.chars().count() > max {
        format!("{}…", t.chars().take(max).collect::<String>())
    } else {
        t.to_string()
    }
}

/// Best-effort open URL in the user browser (account sign-in for xAI / OpenCode).
fn open_browser_url(url: &str) -> bool {
    use std::process::Command;
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(url).spawn().is_ok()
    }
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
            .is_ok()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Command::new("xdg-open").arg(url).spawn().is_ok()
            || Command::new("gio").args(["open", url]).spawn().is_ok()
    }
}

pub async fn run_tui(
    mut app: App,
    mut events: mpsc::Receiver<AgentEvent>,
    user_tx: mpsc::Sender<String>,
    secret_tx: mpsc::Sender<(AuthRequest, oscar_core::SecretKind, String)>,
    cancel_tx: mpsc::Sender<()>,
    config_tx: mpsc::Sender<OscarConfig>,
    mut session_rx: mpsc::Receiver<oscar_core::StoredChatSession>,
    transcript_tx: mpsc::Sender<Vec<TranscriptLine>>,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    // Controllable panes: mouse select/scroll + bracketed paste (Grok Build–style).
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(
        &mut terminal,
        &mut app,
        &mut events,
        &user_tx,
        &secret_tx,
        &cancel_tx,
        &config_tx,
        &mut session_rx,
        &transcript_tx,
    )
    .await;

    // Final save request with latest transcript
    let _ = transcript_tx.send(app.transcript_lines()).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        DisableBracketedPaste,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    events: &mut mpsc::Receiver<AgentEvent>,
    user_tx: &mpsc::Sender<String>,
    secret_tx: &mpsc::Sender<(AuthRequest, oscar_core::SecretKind, String)>,
    cancel_tx: &mpsc::Sender<()>,
    config_tx: &mpsc::Sender<OscarConfig>,
    session_rx: &mut mpsc::Receiver<oscar_core::StoredChatSession>,
    transcript_tx: &mpsc::Sender<Vec<TranscriptLine>>,
) -> io::Result<()> {
    loop {
        app.tick_idle_hint();
        app.tick_activity();
        // Live-update thinking header spinner while thinking
        if matches!(app.activity, AgentActivity::Thinking) && app.thinking_open {
            app.update_thinking_header_live();
        }
        terminal.draw(|f| ui::draw(f, app))?;

        while let Ok(ev) = events.try_recv() {
            app.handle_agent_event(ev);
        }

        // Host pushed a session to load (resume / initial)
        while let Ok(s) = session_rx.try_recv() {
            app.load_transcript(&s.transcript, &s.id, &s.title);
            app.push_line(
                LineKind::System,
                format!(
                    "Loaded chat «{}» ({}) · /new · /history",
                    s.title,
                    &s.id[..s.id.len().min(8)]
                ),
            );
        }

        if let Some(secret) = app.pending_secret.take() {
            let _ = secret_tx.send(secret).await;
        }
        if let Some(user) = app.pending_user.take() {
            let is_history_cmd = user.starts_with("/history")
                || user.starts_with("/sessions")
                || user == "/new"
                || user.starts_with("/resume")
                || user.starts_with("/session");
            let is_setup_cmd = user.starts_with("/provider")
                || user.starts_with("/llm")
                || user.starts_with("/api-key")
                || user.starts_with("/apikey")
                || user.starts_with("/settings")
                || user == "/help"
                || user == "/quit"
                || user == "/exit";
            // Never stream chat turns when no provider — avoids stuck cancel/streaming bug.
            if !app.config.provider_ready && !user.starts_with('/') {
                app.streaming = false;
                app.open_provider_setup(
                    "Chat blocked: no LLM provider ready. Sign in / paste a key first.",
                );
            } else {
                let _ = user_tx.send(user).await;
                if !is_history_cmd && !is_setup_cmd {
                    app.streaming = true;
                }
            }
        }
        if app.pending_session_save {
            app.pending_session_save = false;
            let _ = transcript_tx.try_send(app.transcript_lines());
        }
        if let Some(cfg) = app.pending_config_save.take() {
            let _ = config_tx.send(cfg).await;
        }
        if app.pending_identity_probe {
            app.pending_identity_probe = false;
            let path = app.config.profiles_path.clone();
            let inv = tokio::task::spawn_blocking(move || {
                let binaries = BinaryInventory::detect();
                match ProfileStore::load_path(&path) {
                    Ok(store) => build_identity_inventory(&store, &binaries),
                    Err(e) => {
                        let mut inv = IdentityInventory::default();
                        inv.notes.push(format!("failed to load profiles: {e}"));
                        inv
                    }
                }
            })
            .await
            .unwrap_or_else(|e| {
                let mut inv = IdentityInventory::default();
                inv.notes.push(format!("probe task failed: {e}"));
                inv
            });
            app.apply_identity_inventory(inv);
        }
        if app.cancel_requested {
            app.cancel_requested = false;
            let _ = cancel_tx.send(()).await;
        }
        if app.should_quit {
            break;
        }

        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) => app.on_key(key),
                Event::Mouse(m) => app.on_mouse(m),
                Event::Paste(text) => app.on_paste_event(text),
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
    Ok(())
}
