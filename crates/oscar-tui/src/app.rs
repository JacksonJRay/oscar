use crate::clipboard;
use crate::identities::IdentitiesPane;
use crate::input::{
    composer_inner_height, cursor_row_col, ensure_input_scroll, input_inner_width, layout_input_rows,
    line_end, line_home, move_cursor_visual, IdleHintRotator, InputMode,
};
use crate::provider_pane::{ProviderPane, ProviderPaneAction};
use crate::sessions_pane::{SessionsPane, SessionsPaneAction};
use crate::settings::{SettingsPane, ToolCatalogEntry};
use crate::slash::{is_slash_command, SlashMenu};
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
    /// Preferred / active cloud identity profile id (status bar).
    pub active_profile: Option<String>,
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
    /// Visible command / status notices (slash results) — not hidden like System.
    Notice,
    Error,
}

/// Max transcript ChatLines kept in the TUI buffer (oldest dropped).
pub const MAX_TRANSCRIPT_LINES: usize = 1_500;
/// Max **visual** rows you can scroll back from the bottom (Grok continuous scroll).
/// Higher than message count because one assistant reply may wrap to many rows.
pub const MAX_SCROLL_BACK_ROWS: usize = 4_000;

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
    /// Grok Build–style session picker (`/resume`).
    Sessions(SessionsPane),
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
///
/// Keyboard / click-without-drag: Grok **entry** selection (whole turn / tool card).
/// Mouse drag: Grok **text** selection ([`TextSelection`]) — character ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineSelection {
    pub anchor: usize,
    pub cursor: usize,
}

/// Character position in transcript body text (Grok `col_within_range` spirit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextPos {
    /// Absolute index into `App::lines`.
    pub line_idx: usize,
    /// Unicode scalar offset into that line's **selectable body** (display text).
    pub char_off: usize,
}

/// Linear text selection (mouse drag) — Grok `ActiveTextDrag` / `SelectionKind::Linear`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextSelection {
    pub anchor: TextPos,
    pub head: TextPos,
}

impl TextSelection {
    pub fn normalized(&self) -> (TextPos, TextPos) {
        let a = self.anchor;
        let b = self.head;
        if (a.line_idx, a.char_off) <= (b.line_idx, b.char_off) {
            (a, b)
        } else {
            (b, a)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.anchor == self.head
    }
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

/// Whether two consecutive transcript lines belong to the same copy/select block
/// (Grok “entry”: one assistant answer, one tool card, one user prompt, …).
fn same_block_kind(a: LineKind, b: LineKind) -> bool {
    match (a, b) {
        (LineKind::Assistant, LineKind::Assistant) => true,
        (LineKind::Thinking, LineKind::Thinking) => true,
        (LineKind::Tool, LineKind::Tool) => true,
        (LineKind::Error, LineKind::Error) => true,
        (LineKind::Notice, LineKind::Notice) => true,
        // User / System are one line per entry.
        _ => false,
    }
}

pub struct App {
    pub config: AppConfig,
    pub lines: Vec<ChatLine>,
    pub input: String,
    /// Cursor position in **chars** within `input` (or secure buffer).
    pub input_cursor: usize,
    /// Grok multiline mode: Enter inserts newline; Shift/Alt+Enter sends.
    /// Off (default): Enter sends; Shift/Alt+Enter inserts newline.
    pub multiline_mode: bool,
    /// First visible visual row of the composer when content exceeds max height.
    pub input_scroll: usize,
    /// Last measured terminal height (for composer growth).
    pub last_term_height: u16,
    /// Last measured input pane width (for wrap + cursor).
    pub last_input_width: u16,
    pub input_mode: InputMode,
    pub status: String,
    pub context: Option<ContextSnapshot>,
    pub streaming: bool,
    /// True only for real model chat turns (not slash commands).
    pub awaiting_reply: bool,
    /// Prompts typed while a turn is in flight (Grok Build / OpenCode queue).
    /// Drained automatically on `AgentEvent::Done`.
    pub prompt_queue: std::collections::VecDeque<String>,
    /// Filtered `/` command popup while typing in the input bar.
    pub slash_menu: Option<SlashMenu>,
    pub show_thinking: bool,
    pub should_quit: bool,
    pub view: View,
    /// User messages / slash commands for the host to process.
    pub pending_user: Option<String>,
    /// Submitted secret(s) when secure mode completes (one field or bulk AWS export).
    /// Always a non-empty list; bulk paste sends all kinds in **one** batch so the host
    /// stores them atomically before resume (avoids prepare→auth loops).
    pub pending_secret_batch: Option<(AuthRequest, Vec<(oscar_core::SecretKind, String)>)>,
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
    /// Chat scroll in **visual rows** from the bottom (Grok continuous scroll).
    /// **0 = pinned to newest**; +1 shows one more older pixel-row (not a whole message).
    pub chat_scroll: usize,
    /// When true, new lines keep the viewport pinned to the bottom.
    pub stick_to_bottom: bool,
    /// What the agent is doing right now (thinking / tool / answering).
    pub activity: AgentActivity,
    /// Spinner frame index for live activity.
    pub activity_tick: usize,
    /// Controllable pane focus (prompt vs scrollback).
    pub pane_focus: PaneFocus,
    /// Highlighted **entry** range (keyboard / click). Cleared when a text drag starts.
    pub selection: Option<LineSelection>,
    /// Character-range selection from mouse drag (Grok text selection).
    pub text_selection: Option<TextSelection>,
    /// Brief status flash after copy/paste (also pushed as a system line when useful).
    pub copy_flash: Option<String>,
    /// Cached layout: last drawn chat pane rect (for mouse hit-testing).
    pub chat_area: Option<(u16, u16, u16, u16)>, // x,y,w,h
    /// Exact content rect after border+padding (from last `draw_chat`).
    pub chat_inner: Option<(u16, u16, u16, u16)>, // x,y,w,h
    /// Visual row → absolute transcript line index from last draw (same as pixels).
    /// Length = chat_inner height; `None` = empty top pad.
    pub chat_row_map: Vec<Option<usize>>,
    /// Parallel to `chat_row_map`: character hit info for text selection.
    pub chat_hit_map: Vec<Option<crate::ui::VisualHit>>,
    /// Cached layout: last drawn input pane rect.
    pub input_area: Option<(u16, u16, u16, u16)>,
    /// True while a thinking stream is open (header + body).
    thinking_open: bool,
    /// Chars received in the current thinking block.
    thinking_chars: usize,
    /// Mouse drag exceeded threshold (text selection active).
    mouse_dragging: bool,
    /// Line index under the cursor when left button went down (entry fallback).
    mouse_down_line: Option<usize>,
    /// Screen + text anchor at mouse-down (Grok PendingTextDrag).
    mouse_down_text: Option<(u16, u16, TextPos)>,
    /// Grok-style double-Esc clear prompt (within 800ms).
    esc_clear_armed_at: Option<std::time::Instant>,
    /// Grok-style double-Ctrl+C quit (within 1000ms) when idle + empty.
    ctrl_c_quit_armed_at: Option<std::time::Instant>,
    /// When the copy/status flash should clear (auto-dismiss).
    flash_until: Option<std::time::Instant>,
}

#[derive(Debug, Clone)]
pub enum SessionAction {
    New,
    List,
    Resume(String),
    Delete(String),
}

/// Secure-bar submit: one field or bulk AWS export parse.
enum BulkOrSingle {
    Single(oscar_core::SecretKind, String),
    Bulk(Vec<(oscar_core::SecretKind, String)>),
}

impl App {
    pub fn new(config: AppConfig) -> Self {
        let show_thinking = config.show_thinking;
        let mut app = Self {
            config,
            lines: vec![],
            input: String::new(),
            input_cursor: 0,
            multiline_mode: false,
            input_scroll: 0,
            last_term_height: 40,
            last_input_width: 80,
            input_mode: InputMode::Normal,
            status: String::new(),
            context: None,
            streaming: false,
            awaiting_reply: false,
            prompt_queue: std::collections::VecDeque::new(),
            slash_menu: None,
            show_thinking,
            should_quit: false,
            view: View::Chat,
            pending_user: None,
            pending_secret_batch: None,
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
            text_selection: None,
            copy_flash: None,
            chat_area: None,
            chat_inner: None,
            chat_row_map: Vec::new(),
            chat_hit_map: Vec::new(),
            input_area: None,
            thinking_open: false,
            thinking_chars: 0,
            mouse_dragging: false,
            mouse_down_line: None,
            mouse_down_text: None,
            esc_clear_armed_at: None,
            ctrl_c_quit_armed_at: None,
            flash_until: None,
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

    /// Open Grok-style session picker (browse + resume previous chats).
    pub fn open_sessions_picker(&mut self) {
        self.streaming = false;
        self.awaiting_reply = false;
        self.activity = AgentActivity::Idle;
        self.slash_menu = None;
        let pane = SessionsPane::open(self.session_id.clone());
        let n = pane.all.len();
        self.view = View::Sessions(pane);
        self.push_line(
            LineKind::Notice,
            format!("Resume: {n} saved session(s) · Enter to load · Esc cancel"),
        );
    }

    pub fn close_sessions_picker(&mut self) {
        if matches!(self.view, View::Sessions(_)) {
            self.view = View::Chat;
        }
    }

    /// Open dedicated Provider setup pane (first run / missing key / /provider).
    pub fn open_provider_setup(&mut self, reason: impl Into<String>) {
        // Never interrupt masked key entry — host errors often race the paste flow.
        if matches!(self.input_mode, InputMode::Secure { .. }) {
            self.push_line(
                LineKind::Notice,
                format!("{} (finish or Esc cancel secure key entry first)", reason.into()),
            );
            return;
        }
        let reason = reason.into();
        // Never leave chat stuck in streaming when forcing setup.
        self.streaming = false;
        self.awaiting_reply = false;
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
        self.sync_input_scroll();
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
        self.sync_input_scroll();
    }

    fn input_clear(&mut self) {
        match &mut self.input_mode {
            InputMode::Secure { buffer, .. } => buffer.clear(),
            InputMode::Normal => self.input.clear(),
        }
        self.input_cursor = 0;
        self.input_scroll = 0;
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

    /// Current composer buffer (normal input or secure bar).
    pub fn input_buffer(&self) -> &str {
        match &self.input_mode {
            InputMode::Secure { buffer, .. } => buffer.as_str(),
            InputMode::Normal => self.input.as_str(),
        }
    }

    /// Soft-wrap layout for the composer at the last known pane width.
    pub fn input_rows(&self) -> Vec<crate::input::InputRow> {
        let w = input_inner_width(self.last_input_width.max(12));
        layout_input_rows(self.input_buffer(), w)
    }

    /// Inner content rows the composer should occupy (Grok-style growth).
    pub fn composer_content_rows(&self) -> u16 {
        let rows = self.input_rows();
        composer_inner_height(rows.len(), self.last_term_height.max(8))
    }

    /// Full bordered composer height (content + top/bottom border).
    pub fn composer_pane_height(&self) -> u16 {
        self.composer_content_rows().saturating_add(2).max(3)
    }

    /// Recompute input_scroll so the cursor row stays visible.
    pub fn sync_input_scroll(&mut self) {
        let rows = self.input_rows();
        let text_len = Self::input_char_len(self.input_buffer());
        let (cursor_row, _) = cursor_row_col(&rows, self.input_cursor, text_len);
        let visible = self.composer_content_rows() as usize;
        self.input_scroll = ensure_input_scroll(self.input_scroll, cursor_row, rows.len(), visible);
    }

    fn input_delete_forward(&mut self) {
        let len = Self::input_char_len(self.input_buffer());
        if self.input_cursor >= len {
            return;
        }
        match &mut self.input_mode {
            InputMode::Secure { buffer, .. } => {
                let start = Self::byte_index_at(buffer, self.input_cursor);
                let end = Self::byte_index_at(buffer, self.input_cursor + 1);
                buffer.replace_range(start..end, "");
            }
            InputMode::Normal => {
                let start = Self::byte_index_at(&self.input, self.input_cursor);
                let end = Self::byte_index_at(&self.input, self.input_cursor + 1);
                self.input.replace_range(start..end, "");
            }
        }
    }

    fn input_move_visual(&mut self, drow: i32) {
        let rows = self.input_rows();
        let text_len = Self::input_char_len(self.input_buffer());
        self.input_cursor = move_cursor_visual(&rows, self.input_cursor, text_len, drow);
        self.sync_input_scroll();
    }

    fn input_line_home(&mut self) {
        let rows = self.input_rows();
        let text_len = Self::input_char_len(self.input_buffer());
        self.input_cursor = line_home(&rows, self.input_cursor, text_len);
        self.sync_input_scroll();
    }

    fn input_line_end(&mut self) {
        let rows = self.input_rows();
        let text_len = Self::input_char_len(self.input_buffer());
        self.input_cursor = line_end(&rows, self.input_cursor, text_len);
        self.sync_input_scroll();
    }

    /// Word left (Ctrl+Left) — readline-style.
    fn input_word_left(&mut self) {
        let chars: Vec<char> = self.input_buffer().chars().collect();
        if self.input_cursor == 0 || chars.is_empty() {
            return;
        }
        let mut i = self.input_cursor.min(chars.len());
        // skip whitespace left
        while i > 0 && chars[i - 1].is_whitespace() {
            i -= 1;
        }
        while i > 0 && !chars[i - 1].is_whitespace() {
            i -= 1;
        }
        self.input_cursor = i;
        self.sync_input_scroll();
    }

    /// Word right (Ctrl+Right).
    fn input_word_right(&mut self) {
        let chars: Vec<char> = self.input_buffer().chars().collect();
        let len = chars.len();
        let mut i = self.input_cursor.min(len);
        while i < len && !chars[i].is_whitespace() {
            i += 1;
        }
        while i < len && chars[i].is_whitespace() {
            i += 1;
        }
        self.input_cursor = i;
        self.sync_input_scroll();
    }

    fn input_insert_newline(&mut self) {
        self.input_insert_char('\n');
        self.sync_input_scroll();
    }

    /// Whether Shift/Alt+Enter (or multiline Enter inversion) should insert a newline.
    fn enter_inserts_newline(&self, key: crossterm::event::KeyEvent) -> bool {
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let modified = shift || alt;
        if self.multiline_mode {
            // Multiline: plain Enter = newline; Shift/Alt+Enter = send
            !modified
        } else {
            // Default: plain Enter = send; Shift/Alt+Enter = newline
            modified
        }
    }

    fn toggle_multiline_mode(&mut self) {
        self.multiline_mode = !self.multiline_mode;
        let state = if self.multiline_mode {
            "multiline ON · Enter=newline · Shift/Alt+Enter=send"
        } else {
            "multiline OFF · Enter=send · Shift/Alt+Enter=newline"
        };
        self.set_flash(state);
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

    /// True while a model turn is in flight (queue applies).
    pub fn turn_busy(&self) -> bool {
        self.awaiting_reply || self.streaming
    }

    /// Brief toast on the input title (auto-clears). Prefer over permanent chat notices.
    pub fn set_flash(&mut self, msg: impl Into<String>) {
        self.copy_flash = Some(msg.into());
        self.flash_until = Some(std::time::Instant::now() + std::time::Duration::from_millis(2200));
    }

    /// Call once per frame from the draw/event loop.
    pub fn tick_flash(&mut self) {
        if let Some(until) = self.flash_until {
            if std::time::Instant::now() >= until {
                self.copy_flash = None;
                self.flash_until = None;
            }
        }
    }

    /// Cancel the in-flight agent turn (Grok Esc). Draft is preserved.
    pub fn request_cancel_turn(&mut self) {
        if !self.turn_busy() {
            return;
        }
        self.cancel_requested = true;
        self.streaming = false;
        self.awaiting_reply = false;
        self.activity = AgentActivity::Idle;
        self.set_flash("Cancel requested — stopping generation…");
        // Keep prompt_queue; user may still want queued follow-ups after cancel.
    }

    /// Grok Esc ladder for chat (never quit on a single Esc).
    pub fn handle_esc_chat(&mut self) {
        // 1) Slash menu
        if self.slash_menu.is_some() {
            self.slash_menu = None;
            self.esc_clear_armed_at = None;
            return;
        }
        // 2) Secure bar cancel
        if matches!(self.input_mode, InputMode::Secure { .. }) {
            self.input_mode = InputMode::Normal;
            self.input_cursor = 0;
            self.set_flash("Credential entry cancelled");
            self.esc_clear_armed_at = None;
            return;
        }
        // 3) Selection clear (text drag or entry)
        if (self.selection.is_some() || self.text_selection.is_some())
            && self.pane_focus == PaneFocus::Scrollback
        {
            self.selection = None;
            self.text_selection = None;
            self.set_flash("Selection cleared");
            self.esc_clear_armed_at = None;
            return;
        }
        // 4) Cancel running turn (draft kept)
        if self.turn_busy() {
            self.request_cancel_turn();
            self.esc_clear_armed_at = None;
            return;
        }
        // 5) Double-Esc clear non-empty prompt (Grok ~800ms)
        if self.pane_focus == PaneFocus::Prompt && !self.input.is_empty() {
            let now = std::time::Instant::now();
            if let Some(t0) = self.esc_clear_armed_at {
                if now.duration_since(t0) <= std::time::Duration::from_millis(800) {
                    self.input.clear();
                    self.input_cursor = 0;
                    self.slash_menu = None;
                    self.esc_clear_armed_at = None;
                    self.set_flash("Prompt cleared");
                    return;
                }
            }
            self.esc_clear_armed_at = Some(now);
            self.set_flash("Press Esc again to clear prompt");
            return;
        }
        // 6) Scrollback focused → return to prompt (do not quit)
        if self.pane_focus == PaneFocus::Scrollback {
            self.focus_prompt();
            self.esc_clear_armed_at = None;
            return;
        }
        // Idle empty prompt: swallow Esc (Grok does not quit here)
        self.esc_clear_armed_at = None;
        self.set_flash("Esc: cancel turn · Esc Esc: clear prompt · /quit to exit");
    }

    /// Grok Ctrl+C: clear draft → cancel turn → double-press quit.
    pub fn handle_ctrl_c_chat(&mut self) {
        if matches!(self.input_mode, InputMode::Secure { .. }) {
            self.input_mode = InputMode::Normal;
            self.input_cursor = 0;
            self.set_flash("Credential entry cancelled");
            self.ctrl_c_quit_armed_at = None;
            return;
        }
        if !self.input.is_empty() {
            self.input.clear();
            self.input_cursor = 0;
            self.slash_menu = None;
            self.set_flash("Prompt cleared (Ctrl+C again cancels / quits)");
            self.ctrl_c_quit_armed_at = None;
            return;
        }
        if self.turn_busy() {
            self.request_cancel_turn();
            self.ctrl_c_quit_armed_at = None;
            return;
        }
        let now = std::time::Instant::now();
        if let Some(t0) = self.ctrl_c_quit_armed_at {
            if now.duration_since(t0) <= std::time::Duration::from_millis(1000) {
                self.should_quit = true;
                return;
            }
        }
        self.ctrl_c_quit_armed_at = Some(now);
        self.set_flash("Press Ctrl+C again to quit");
    }

    /// Restore display transcript from a saved session.
    /// Always pins viewport to the **bottom** (newest) so loading history does not leave the user mid-scroll.
    pub fn load_transcript(&mut self, lines: &[TranscriptLine], session_id: &str, title: &str) {
        // Same session re-push (host bootstrap) must NOT wipe live chat lines /
        // SSE notices / in-flight deltas. Only replace the buffer when switching
        // to a different session id (resume /new).
        let same_session = self.session_id == session_id && !self.session_id.is_empty();
        self.session_id = session_id.into();
        self.session_title = title.into();
        if same_session && !self.lines.is_empty() {
            return;
        }
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
                    "notice" => LineKind::Notice,
                    _ => LineKind::System,
                },
                text: l.text.clone(),
            })
            .collect();
        let start = mapped.len().saturating_sub(MAX_TRANSCRIPT_LINES);
        // Drop legacy chrome system banners from restored transcript (session id, tips).
        self.lines = mapped[start..]
            .iter()
            .filter(|l| !matches!(l.kind, LineKind::System))
            .cloned()
            .collect();
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

    /// Lines shown in the chat pane (excludes blue system chrome).
    pub fn visible_line_indices(&self) -> Vec<usize> {
        self.lines
            .iter()
            .enumerate()
            .filter(|(_, l)| !matches!(l.kind, LineKind::System))
            .map(|(i, _)| i)
            .collect()
    }

    /// Viewport height in visual rows (content area), when known.
    pub fn viewport_rows(&self) -> usize {
        self.chat_inner
            .map(|(_, _, _, h)| h as usize)
            .or_else(|| self.chat_area.map(|(_, _, _, h)| h.saturating_sub(4) as usize))
            .unwrap_or(20)
            .max(1)
    }

    /// Viewport width in columns (content area), when known.
    pub fn viewport_cols(&self) -> usize {
        self.chat_inner
            .map(|(_, _, w, _)| w as usize)
            .or_else(|| self.chat_area.map(|(_, _, w, _)| w.saturating_sub(4) as usize))
            .unwrap_or(80)
            .max(8)
    }

    /// Max visual-row scroll offset from bottom (Grok continuous scroll, hard cap).
    pub fn max_chat_scroll(&self) -> usize {
        let height = self.viewport_rows();
        let width = self.viewport_cols();
        let total = crate::ui::count_chat_visual_rows(self, width);
        total.saturating_sub(height).min(MAX_SCROLL_BACK_ROWS)
    }

    /// Refresh the `/` command popup from the current input buffer.
    ///
    /// Shows **immediately** on bare `/` and filters as the user types (`/m` → model…).
    /// Works even while a turn is streaming (Grok Build / OpenCode style).
    pub fn refresh_slash_menu(&mut self) {
        if matches!(self.input_mode, InputMode::Normal) && matches!(self.view, View::Chat) {
            // Typing into `/` always means the prompt owns focus.
            if self.input.starts_with('/') {
                self.pane_focus = PaneFocus::Prompt;
            }
            let keep = self
                .slash_menu
                .as_ref()
                .and_then(|m| m.selected_cmd())
                .map(|c| c.name);
            self.slash_menu = SlashMenu::from_input_preserving(&self.input, keep);
        } else {
            self.slash_menu = None;
        }
    }

    /// Scroll chat history by **visual rows** (Grok: wheel/Ctrl+J/K = continuous).
    /// Positive = older (up), negative = newer (down toward bottom).
    pub fn scroll_chat(&mut self, delta: i32) {
        if delta == 0 {
            return;
        }
        let max = self.max_chat_scroll() as i32;
        // No "softening" — delta is exact visual rows so scroll never snaps by whole messages.
        let next = (self.chat_scroll as i32 + delta).clamp(0, max);
        self.chat_scroll = next as usize;
        self.stick_to_bottom = self.chat_scroll == 0;
        if self.chat_scroll > 0 {
            self.pane_focus = PaneFocus::Scrollback;
        }
    }

    /// Page scroll: full viewport of visual rows (Grok PageUp/PageDown).
    pub fn scroll_chat_page(&mut self, up: bool) {
        let page = self.viewport_rows().max(1) as i32;
        if up {
            self.scroll_chat(page);
        } else {
            self.scroll_chat(-page);
        }
    }

    /// Half-page scroll (Grok Ctrl+U / Ctrl+D).
    pub fn scroll_chat_half_page(&mut self, up: bool) {
        let half = (self.viewport_rows().max(2) / 2) as i32;
        if up {
            self.scroll_chat(half);
        } else {
            self.scroll_chat(-half);
        }
    }

    /// Focus the prompt (composer). Clears scrollback-only key modes.
    pub fn focus_prompt(&mut self) {
        self.pane_focus = PaneFocus::Prompt;
        // Keep selection highlight visible briefly? Grok clears when typing — keep until leave.
    }

    /// Expand a line index to the full Grok-style entry block it belongs to.
    pub fn block_bounds(&self, idx: usize) -> (usize, usize) {
        if idx >= self.lines.len() {
            return (0, 0);
        }
        let kind = self.lines[idx].kind;
        if matches!(kind, LineKind::System) {
            return (idx, idx);
        }
        let mut start = idx;
        while start > 0 {
            let prev = start - 1;
            if matches!(self.lines[prev].kind, LineKind::System) {
                break;
            }
            if !same_block_kind(self.lines[prev].kind, kind) {
                break;
            }
            start = prev;
        }
        let mut end = idx;
        while end + 1 < self.lines.len() {
            let next = end + 1;
            if matches!(self.lines[next].kind, LineKind::System) {
                break;
            }
            if !same_block_kind(kind, self.lines[next].kind) {
                break;
            }
            end = next;
        }
        (start, end)
    }

    /// Select the whole entry/block that contains `idx` (Grok click-to-select-entry).
    pub fn select_block_at(&mut self, idx: usize) {
        if idx >= self.lines.len() || matches!(self.lines[idx].kind, LineKind::System) {
            return;
        }
        let (start, end) = self.block_bounds(idx);
        self.selection = Some(LineSelection {
            anchor: start,
            cursor: end,
        });
        self.pane_focus = PaneFocus::Scrollback;
        self.stick_to_bottom = false;
        self.ensure_selection_visible();
    }

    /// Ordered list of block start indices among visible lines (for j/k entry nav).
    pub fn block_starts(&self) -> Vec<usize> {
        let indices = self.visible_line_indices();
        let mut starts = Vec::new();
        let mut i = 0usize;
        while i < indices.len() {
            let abs = indices[i];
            let (s, e) = self.block_bounds(abs);
            starts.push(s);
            // Advance past this block in the visible list
            while i < indices.len() && indices[i] <= e {
                i += 1;
            }
        }
        starts
    }

    /// Focus the chat scrollback and ensure a selection exists.
    pub fn focus_scrollback(&mut self) {
        self.pane_focus = PaneFocus::Scrollback;
        if self.selection.is_none() {
            // Prefer newest *assistant* block, else newest visible entry (Grok-style).
            let starts = self.block_starts();
            if let Some(&last) = starts.last() {
                // Prefer last assistant block when available
                let prefer = starts
                    .iter()
                    .rev()
                    .find(|&&s| {
                        self.lines
                            .get(s)
                            .map(|l| l.kind == LineKind::Assistant)
                            .unwrap_or(false)
                    })
                    .copied()
                    .unwrap_or(last);
                self.select_block_at(prefer);
            }
        }
        self.stick_to_bottom = false;
    }

    pub fn toggle_pane_focus(&mut self) {
        match self.pane_focus {
            PaneFocus::Prompt => self.focus_scrollback(),
            PaneFocus::Scrollback => self.focus_prompt(),
        }
    }

    /// Move selection by `delta` **blocks** (Grok j/k entry nav). Shift extends range.
    pub fn move_selection(&mut self, delta: i32, extend: bool) {
        let starts = self.block_starts();
        if starts.is_empty() {
            return;
        }
        let last_pos = starts.len() - 1;
        let cur_abs = self
            .selection
            .map(|s| s.cursor)
            .unwrap_or(*starts.last().unwrap());
        // Which block contains the cursor?
        let cur_pos = starts
            .iter()
            .rposition(|&s| {
                let (_, e) = self.block_bounds(s);
                cur_abs >= s && cur_abs <= e
            })
            .unwrap_or(last_pos);
        let next_pos = (cur_pos as i32 + delta).clamp(0, last_pos as i32) as usize;
        let next_start = starts[next_pos];
        let (ns, ne) = self.block_bounds(next_start);
        if extend {
            let anchor_line = self.selection.map(|s| s.anchor).unwrap_or(ns);
            let (aa, ab) = self.block_bounds(anchor_line);
            let lo = aa.min(ns);
            let hi = ab.max(ne);
            self.selection = Some(LineSelection {
                anchor: lo,
                cursor: hi,
            });
        } else {
            self.selection = Some(LineSelection {
                anchor: ns,
                cursor: ne,
            });
        }
        self.ensure_selection_visible();
        self.pane_focus = PaneFocus::Scrollback;
    }

    /// Keep the selection cursor inside the visible viewport by adjusting visual scroll.
    pub fn ensure_selection_visible(&mut self) {
        let Some(sel) = self.selection else {
            return;
        };
        let width = self.viewport_cols();
        let height = self.viewport_rows();
        // Distance of selection's bottom visual row from transcript bottom.
        let from_bottom =
            crate::ui::visual_rows_from_bottom_to_line(self, width, sel.cursor);
        // Want selection inside [scroll, scroll+height)
        if from_bottom < self.chat_scroll {
            // Selection is below viewport (newer than scroll window) → scroll down
            self.chat_scroll = from_bottom;
        } else if from_bottom >= self.chat_scroll + height {
            // Selection is above viewport → scroll up so it sits near top
            self.chat_scroll = from_bottom.saturating_sub(height.saturating_sub(1));
        }
        self.chat_scroll = self.chat_scroll.min(self.max_chat_scroll());
        self.stick_to_bottom = self.chat_scroll == 0 && self.pane_focus == PaneFocus::Prompt;
    }

    /// Format lines for clipboard — Grok copies **block content**, not `role: text` dumps.
    fn format_lines_for_copy(lines: &[&ChatLine]) -> String {
        if lines.is_empty() {
            return String::new();
        }
        // Homogeneous assistant / user / notice → plain body (best for pasting into editors).
        let kinds: Vec<LineKind> = lines.iter().map(|l| l.kind).collect();
        let all_assistant = kinds.iter().all(|k| *k == LineKind::Assistant);
        let all_user = kinds.iter().all(|k| *k == LineKind::User);
        let all_tool = kinds.iter().all(|k| *k == LineKind::Tool);
        let all_thinking = kinds.iter().all(|k| *k == LineKind::Thinking);

        if all_assistant || all_user || all_tool || all_thinking {
            return lines
                .iter()
                .map(|l| {
                    let t = l.text.as_str();
                    // Strip thinking rail prefix for clean paste
                    if all_thinking {
                        t.trim_start_matches('│')
                            .trim_start_matches('┃')
                            .trim_start()
                            .to_string()
                    } else {
                        t.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
        }

        // Mixed selection: light section labels (still no noisy "assistant:" on every wrap line).
        let mut out = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let kind = lines[i].kind;
            let mut j = i + 1;
            while j < lines.len() && same_block_kind(kind, lines[j].kind) {
                j += 1;
            }
            let body: String = lines[i..j]
                .iter()
                .map(|l| l.text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let label = match kind {
                LineKind::User => "User",
                LineKind::Assistant => "Assistant",
                LineKind::Thinking => "Thinking",
                LineKind::Tool => "Tool",
                LineKind::Notice => "Notice",
                LineKind::Error => "Error",
                LineKind::System => "System",
            };
            out.push(format!("## {label}\n{body}"));
            i = j;
        }
        out.join("\n\n")
    }

    /// Full chat pane text (visible lines only — skips hidden system chrome).
    pub fn full_chat_text(&self) -> Option<String> {
        let indices = self.visible_line_indices();
        if indices.is_empty() {
            return None;
        }
        let refs: Vec<&ChatLine> = indices
            .into_iter()
            .filter_map(|i| self.lines.get(i))
            .collect();
        let text = Self::format_lines_for_copy(&refs);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    /// Text for the current multi-line (or single-line) **highlight only**.
    /// Returns None if there is no selection — does not fall back to full chat.
    pub fn selection_text(&self) -> Option<String> {
        let sel = self.selection?;
        let (a, b) = sel.range();
        if a >= self.lines.len() {
            return None;
        }
        let end = b.min(self.lines.len() - 1);
        let refs: Vec<&ChatLine> = (a..=end)
            .filter_map(|i| {
                let l = self.lines.get(i)?;
                if matches!(l.kind, LineKind::System) {
                    None
                } else {
                    Some(l)
                }
            })
            .collect();
        let text = Self::format_lines_for_copy(&refs);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    /// Copy: prefer **text selection** (Grok drag), else entry block, else latest assistant.
    pub fn copy_selection(&mut self) {
        let (text, what) = if let Some(t) = self.text_selection_string() {
            let n = t.chars().count();
            (t, format!("text · {n} chars"))
        } else if self.selection.is_some() {
            if let Some(t) = self.selection_text() {
                let n = self.selection.map(|s| s.line_count()).unwrap_or(1);
                let kind = self
                    .selection
                    .and_then(|s| self.lines.get(s.range().0))
                    .map(|l| match l.kind {
                        LineKind::Assistant => "assistant block",
                        LineKind::User => "user block",
                        LineKind::Tool => "tool block",
                        LineKind::Thinking => "thinking block",
                        LineKind::Error => "error block",
                        LineKind::Notice => "notice block",
                        LineKind::System => "block",
                    })
                    .unwrap_or("block");
                (t, format!("{kind} · {n} line(s)"))
            } else {
                self.set_flash("Nothing to copy");
                return;
            }
        } else if let Some(t) = self.nth_assistant_text(1) {
            (t, "latest assistant reply".into())
        } else if let Some(t) = self.full_chat_text() {
            let n = self.visible_line_indices().len();
            (t, format!("full chat · {n} line(s)"))
        } else {
            self.set_flash("Nothing to copy");
            return;
        };
        let outcome = clipboard::copy_text(&text);
        self.set_flash(format!("{} · {what}", outcome.message));
    }

    /// Copy the entire chat pane (all visible transcript lines). Explicit only (`/copy all`).
    pub fn copy_full_chat(&mut self) {
        let Some(text) = self.full_chat_text() else {
            self.set_flash("Nothing to copy");
            return;
        };
        let n = self.visible_line_indices().len();
        let outcome = clipboard::copy_text(&text);
        self.set_flash(format!("{} · full chat · {n} line(s)", outcome.message));
    }

    fn nth_assistant_text(&self, n: usize) -> Option<String> {
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
        if blocks.is_empty() || n > blocks.len() {
            return None;
        }
        Some(blocks[blocks.len() - n].clone())
    }

    /// `/copy` [n] — copy Nth-latest assistant reply (1 = most recent). Grok `/copy`.
    pub fn copy_nth_assistant(&mut self, n: usize) {
        let n = n.max(1);
        let Some(text) = self.nth_assistant_text(n) else {
            let count = {
                let mut c = 0usize;
                let mut in_a = false;
                for l in &self.lines {
                    if l.kind == LineKind::Assistant {
                        if !in_a {
                            c += 1;
                            in_a = true;
                        }
                    } else {
                        in_a = false;
                    }
                }
                c
            };
            if count == 0 {
                self.set_flash("No assistant replies to copy");
            } else {
                self.set_flash(format!("Only {count} assistant reply block(s)"));
            }
            return;
        };
        let outcome = clipboard::copy_text(&text);
        self.set_flash(format!("{} · assistant reply #{n}", outcome.message));
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
            self.refresh_slash_menu();
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
        self.sync_input_scroll();
    }

    fn chat_content_rect(&self) -> Option<(u16, u16, u16, u16)> {
        if let Some(inner) = self.chat_inner {
            Some(inner)
        } else {
            let (x, y, w, h) = self.chat_area?;
            Some((
                x.saturating_add(1),
                y.saturating_add(1),
                w.saturating_sub(2).max(1),
                h.saturating_sub(2).max(1),
            ))
        }
    }

    /// Map mouse Y within the chat area to a transcript line index, if any.
    pub fn line_index_at_mouse(&self, col: u16, row: u16) -> Option<usize> {
        let (ix, iy, iw, ih) = self.chat_content_rect()?;
        if col < ix || col >= ix.saturating_add(iw) || row < iy || row >= iy.saturating_add(ih) {
            return None;
        }
        let row_in = (row - iy) as usize;
        if !self.chat_row_map.is_empty() {
            return self.chat_row_map.get(row_in).copied().flatten();
        }
        let map = crate::ui::chat_visual_row_map(self, iw as usize, ih as usize);
        map.get(row_in).copied().flatten()
    }

    /// Grok-style character hit under the pointer (line + col within body).
    pub fn text_pos_at_mouse(&self, col: u16, row: u16) -> Option<TextPos> {
        let (ix, iy, iw, ih) = self.chat_content_rect()?;
        if col < ix || col >= ix.saturating_add(iw) || row < iy || row >= iy.saturating_add(ih) {
            return None;
        }
        let row_in = (row - iy) as usize;
        let hit = self.chat_hit_map.get(row_in)?.as_ref()?;
        let char_off = hit.char_at_screen_col(col, ix);
        Some(TextPos {
            line_idx: hit.line_idx,
            char_off,
        })
    }

    /// Extract selected characters (display body). Empty if no text selection.
    pub fn text_selection_string(&self) -> Option<String> {
        let sel = self.text_selection?;
        if sel.is_empty() {
            return None;
        }
        let (a, b) = sel.normalized();
        let mut out = String::new();
        for li in a.line_idx..=b.line_idx {
            let body = crate::ui::selectable_body_text(self, li);
            let chars: Vec<char> = body.chars().collect();
            let start = if li == a.line_idx {
                a.char_off.min(chars.len())
            } else {
                0
            };
            let end = if li == b.line_idx {
                b.char_off.min(chars.len())
            } else {
                chars.len()
            };
            if start < end {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.extend(chars[start..end].iter());
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
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
            // Grok continuous scroll: one visual row per wheel notch (not a whole message).
            MouseEventKind::ScrollUp => {
                self.scroll_chat(3); // typical terminal sends one event per notch; 3 rows feels natural
            }
            MouseEventKind::ScrollDown => {
                self.scroll_chat(-3);
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if Self::point_in_rect(col, row, self.input_area) {
                    self.focus_prompt();
                    self.mouse_dragging = false;
                    self.mouse_down_line = None;
                    self.mouse_down_text = None;
                    self.text_selection = None;
                    return;
                }
                // Grok: mouse-down anchors a *text* drag; click without drag selects entry.
                if let Some(pos) = self.text_pos_at_mouse(col, row) {
                    self.pane_focus = PaneFocus::Scrollback;
                    self.stick_to_bottom = false;
                    self.mouse_dragging = false;
                    self.mouse_down_line = Some(pos.line_idx);
                    self.mouse_down_text = Some((col, row, pos));
                    // Clear previous text selection; entry select deferred until mouse-up.
                    self.text_selection = None;
                } else if Self::point_in_rect(col, row, self.chat_area) {
                    self.mouse_dragging = false;
                    self.mouse_down_line = None;
                    self.mouse_down_text = None;
                    self.text_selection = None;
                    self.pane_focus = PaneFocus::Scrollback;
                    self.stick_to_bottom = false;
                }
            }
            MouseEventKind::Drag(MouseButton::Left) => {
                // Grok text selection: drag updates head by character, not whole turns.
                if let Some((sx, sy, anchor)) = self.mouse_down_text {
                    let moved = col.abs_diff(sx) >= 2 || row.abs_diff(sy) >= 1;
                    if moved {
                        self.mouse_dragging = true;
                        // Leave entry-block mode while dragging text.
                        self.selection = None;
                        if let Some(head) = self.text_pos_at_mouse(col, row) {
                            self.text_selection = Some(TextSelection { anchor, head });
                        }
                    }
                }
            }
            MouseEventKind::Up(MouseButton::Left) => {
                if self.mouse_dragging {
                    // Finished character drag — copy selected text (Grok: selection ready to copy).
                    if self.text_selection_string().is_some() {
                        self.copy_selection();
                    }
                } else if let Some(idx) = self.mouse_down_line {
                    // Click without drag: Grok entry select (whole block) for `y`.
                    self.text_selection = None;
                    self.select_block_at(idx);
                }
                self.mouse_dragging = false;
                self.mouse_down_line = None;
                self.mouse_down_text = None;
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
                    LineKind::Notice => "notice",
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
        self.lines.clear();
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

    /// Max chars for the profile segment on the top status row.
    pub const STATUS_PROFILE_MAX_CHARS: usize = 28;

    pub fn refresh_status(&mut self) {
        // Top bar: oscar │ mode │ context │ profile │ activity (Grok Build–style working state).
        let ctx = self
            .context
            .as_ref()
            .map(|c| c.format_short())
            .unwrap_or_else(|| "— / — (—%)".into());
        let profile = Self::format_status_profile(
            self.config
                .active_profile
                .as_deref()
                .filter(|s| !s.is_empty()),
            self.config.profile_count,
        );
        let activity = self
            .activity_label()
            .or_else(|| {
                if self.awaiting_reply || self.streaming {
                    Some(format!("{} working", self.spinner_frame()))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "ready".into());
        self.status = format!(
            "oscar │ {} │ {} │ {} │ {}",
            self.config.mode, ctx, profile, activity
        );
    }

    /// Cap profile id for the status bar; fall back to count or em dash.
    pub fn format_status_profile(active: Option<&str>, profile_count: usize) -> String {
        match active {
            Some(id) => {
                let id = id.trim();
                if id.is_empty() {
                    return if profile_count > 0 {
                        format!("profiles:{profile_count}")
                    } else {
                        "—".into()
                    };
                }
                let n = id.chars().count();
                if n <= Self::STATUS_PROFILE_MAX_CHARS {
                    id.to_string()
                } else {
                    let take = Self::STATUS_PROFILE_MAX_CHARS.saturating_sub(1);
                    let truncated: String = id.chars().take(take).collect();
                    format!("{truncated}…")
                }
            }
            None if profile_count > 0 => format!("profiles:{profile_count}"),
            None => "—".into(),
        }
    }

    /// Update active cloud profile (identity pivot / auth resume).
    pub fn set_active_profile(&mut self, profile_id: Option<String>) {
        self.config.active_profile = profile_id
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        self.refresh_status();
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
        let id = provider_id.trim();
        if id.is_empty() {
            return;
        }
        self.config.provider_ready = true;
        self.config.provider = id.to_string();
        self.config.oscar_config.provider.id = id.to_string();
        if let Some(m) = model.filter(|s| !s.is_empty() && *s != "—") {
            self.config.model = m.to_string();
            self.config.oscar_config.provider.model = Some(m.to_string());
        } else if self.config.model.is_empty() || self.config.model == "—" {
            let m = oscar_providers::default_model_for(id);
            self.config.model = m.clone();
            self.config.oscar_config.provider.model = Some(m);
        }
        if self.config.oscar_config.provider.base_url.is_none() {
            self.config.oscar_config.provider.base_url = oscar_providers::default_base_url(id);
        }
        self.config
            .oscar_config
            .providers
            .entry(id.to_string())
            .or_insert_with(|| oscar_core::config::ProviderSlot {
                model: self.config.oscar_config.provider.model.clone(),
                base_url: self.config.oscar_config.provider.base_url.clone(),
                ..Default::default()
            });
        self.refresh_status();
    }

    /// Re-check AuthStore/keychain for the active provider (call after key paste path).
    pub fn refresh_provider_ready(&mut self) {
        let id = self.config.provider.clone();
        let ready = oscar_core::Paths::discover()
            .ok()
            .map(|paths| oscar_providers::provider_has_credentials(&paths, &id))
            .unwrap_or(false);
        self.config.provider_ready = ready;
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
        self.config.provider_ready = oscar_core::Paths::discover()
            .ok()
            .map(|paths| oscar_providers::provider_has_credentials(&paths, &cfg.provider.id))
            .unwrap_or(false);
        self.refresh_status();
    }

    pub fn handle_agent_event(&mut self, ev: AgentEvent) {
        match ev {
            AgentEvent::ContentDelta { text } => {
                // Quiet hub: never surface SSE bind / remote-echo chrome in chat.
                let trimmed = text.trim();
                if trimmed.starts_with("[sse]")
                    || trimmed.contains("[sse] http://")
                    || trimmed.contains("[sse] https://")
                {
                    return;
                }
                // Session preferred cloud profile (system.access.select / prepare).
                if let Some(pid) = extract_active_profile_from_notice(&text) {
                    if pid == "—" || pid.eq_ignore_ascii_case("none") || pid.is_empty() {
                        self.set_active_profile(None);
                    } else {
                        self.set_active_profile(Some(pid));
                    }
                    // Keep as a quiet notice (not assistant chat).
                    let t = text.trim();
                    if !t.is_empty() {
                        self.push_line(LineKind::Notice, t.to_string());
                    }
                    return;
                }
                // Host stored LLM key (secure bar) and/or finished agent rebuild.
                if text.contains("[provider ready")
                    || text.contains("[secure bar] stored API key for provider")
                {
                    let pid = extract_provider_id_from_notice(&text)
                        .unwrap_or_else(|| self.config.provider.clone());
                    self.mark_provider_ready(&pid, None);
                    // Trust the host store notice even if a momentary re-check fails.
                    self.config.provider_ready = true;
                    // Leave any provider modal so chat is usable immediately.
                    if matches!(self.view, View::Provider(_)) {
                        self.view = View::Chat;
                    }
                    if matches!(self.input_mode, InputMode::Secure { .. }) {
                        self.input_mode = InputMode::Normal;
                        self.input_cursor = 0;
                    }
                    self.push_line(LineKind::Notice, text.trim().to_string());
                    return;
                }
                // Slash / host commands: show as notice, never as assistant chat.
                // One ChatLine per logical line so scrollback height matches content
                // (/model list used to jam 40+ models into a single line with \n,
                // which ratatui rendered as one wrapped blob and broke viewport math).
                if !self.awaiting_reply {
                    if let Some((pid, mid)) = extract_model_switch_from_notice(&text) {
                        self.mark_provider_ready(&pid, Some(&mid));
                    }
                    let t = text.trim_start_matches('\n').trim_end_matches('\n');
                    if !t.is_empty() {
                        for chunk in t.split('\n') {
                            self.push_line(LineKind::Notice, chunk.to_string());
                        }
                    }
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
                        format!("Thought… {}", self.spinner_frame()),
                    );
                } else {
                    // Keep header live with spinner + char count
                    self.update_thinking_header_live();
                }
                if self.show_thinking && !text.is_empty() {
                    // Body lines under the header (dim rail in draw)
                    if self
                        .lines
                        .last()
                        .map(|l| {
                            l.kind == LineKind::Thinking
                                && (l.text.starts_with('│') || l.text.starts_with('┃'))
                        })
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
                // Grok-style: after thinking ends, keep the header chip; drop body
                // rail lines so the scrollback stays scannable (toggle Ctrl+T for live body).
                self.collapse_thinking_bodies();
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
                // Grok Build–style tool rail: ◆ header, detail, ✓ close
                self.push_line(LineKind::Tool, String::from("◆ tools_search"));
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
                // Running card (Grok: ◆ tool name + redacted args under rail)
                self.push_line(LineKind::Tool, format!("◆ {tool_id}"));
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
                // Status-only (system lines are hidden from the chat pane).
                self.copy_flash = Some(format!("Compacting ({reason:?})…"));
            }
            AgentEvent::CompactionFinished { before, after } => {
                self.copy_flash = Some(format!(
                    "Compacted {} → {}",
                    before.format_short(),
                    after.format_short()
                ));
                self.context = Some(after);
                self.refresh_status();
            }
            AgentEvent::AuthRequired(auth) => {
                let reauth = if auth.reauth {
                    " [EXPIRED — re-auth]"
                } else {
                    " [missing]"
                };
                // Use Error (not System) so auth guidance stays visible in chat.
                self.push_line(
                    LineKind::Error,
                    format!("Credentials needed{reauth}: {}", auth.reason),
                );
                if let Some(g) = &auth.guidance {
                    self.push_line(LineKind::Error, format!("guidance: {g}"));
                }
                if !auth.hint_commands.is_empty() {
                    self.push_line(
                        LineKind::Error,
                        format!("try: {}", auth.hint_commands.join(" | ")),
                    );
                }
                self.push_line(
                    LineKind::Error,
                    "After auth, oscar auto-retries the paused tool. Secrets go to OS keychain only — the agent never sees pasted values.",
                );
                if auth.kinds.is_empty() {
                    self.push_line(
                        LineKind::Error,
                        "No secret fields to paste — run the hint command (e.g. aws sso login), then type `retry`.",
                    );
                } else {
                    let fields: Vec<_> = auth.kinds.iter().map(|k| format!("{k:?}")).collect();
                    self.push_line(
                        LineKind::Error,
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
                    LineKind::Error,
                    format!(
                        "Paused tool `{}` until credentials ready (reauth={})",
                        tool_id, auth.reauth
                    ),
                );
                self.streaming = false;
            }
            AgentEvent::AuthResumed { tool_id, profile_id } => {
                if let Some(pid) = profile_id.as_ref().filter(|s| !s.is_empty()) {
                    self.set_active_profile(Some(pid.clone()));
                }
                self.push_line(
                    LineKind::Tool,
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
                    LineKind::Error,
                    format!("Admin install approval needed ({intent}): {reason}"),
                );
                if !packages.is_empty() {
                    self.push_line(
                        LineKind::Error,
                        format!("packages: {}", packages.join(", ")),
                    );
                }
                for c in &commands {
                    self.push_line(LineKind::Error, format!("  $ {c}"));
                }
                self.push_line(
                    LineKind::Error,
                    "Type `approve install` to run elevated install, or `deny install` to skip.",
                );
                self.push_line(
                    LineKind::Error,
                    "Or open /settings → Install binaries.",
                );
                self.streaming = false;
            }
            AgentEvent::InstallCompleted { ok, summary } => {
                self.push_line(
                    if ok {
                        LineKind::Tool
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
                let low = message.to_ascii_lowercase();
                let needs_provider = low.contains("no llm provider")
                    || low.contains("provider not ready")
                    || low.contains("no api key for provider")
                    || low.contains("no credentials for provider")
                    || low.contains("provider-key");
                self.push_line(LineKind::Error, message);
                // Re-check AuthStore before bouncing — key paste often races this error.
                if needs_provider && !matches!(self.input_mode, InputMode::Secure { .. }) {
                    self.refresh_provider_ready();
                    if !self.config.provider_ready {
                        self.open_provider_setup(
                            "LLM provider missing or not ready — select a provider and paste an API key.",
                        );
                    }
                }
            }
            AgentEvent::Done { .. } => {
                self.awaiting_reply = false;
                if self.thinking_open {
                    self.finish_thinking_header();
                }
                self.streaming = false;
                self.activity = AgentActivity::Idle;
                self.pending_session_save = true;
                // Grok: brief toast, not permanent chat spam every turn.
                let will_dequeue = !self.prompt_queue.is_empty();
                if !will_dequeue && !matches!(self.input_mode, InputMode::Secure { .. }) {
                    self.set_flash("✓ done — ready");
                }
                // Only snap to newest when following the live tail.
                if self.stick_to_bottom {
                    self.pin_to_bottom();
                }
                self.refresh_status();
                // Prompt queue: auto-send next chat message (Grok Build / OpenCode).
                if let Some(next) = self.prompt_queue.pop_front() {
                    let left = self.prompt_queue.len();
                    if left > 0 {
                        self.set_flash(format!("dequeue · {left} still queued"));
                    } else {
                        self.set_flash("dequeue next prompt");
                    }
                    self.push_line(LineKind::User, next.clone());
                    self.awaiting_reply = true;
                    self.streaming = true;
                    self.activity = AgentActivity::Thinking;
                    self.pending_user = Some(next);
                    if self.stick_to_bottom {
                        self.pin_to_bottom();
                    }
                    self.refresh_status();
                }
            }
        }
    }

    fn update_thinking_header_live(&mut self) {
        let sp = self.spinner_frame();
        let n = self.thinking_chars;
        if let Some(line) = self.lines.iter_mut().rev().find(|l| {
            l.kind == LineKind::Thinking
                && (l.text.contains("Thought") || l.text.contains("thinking"))
                && !l.text.starts_with('│')
                && !l.text.starts_with('┃')
        }) {
            line.text = format!("Thought… ({n} chars) {sp}");
        }
    }

    /// Drop thinking body rails (`│` / `┃`) leaving `Thought · done` headers only.
    fn collapse_thinking_bodies(&mut self) {
        self.lines.retain(|l| {
            !(l.kind == LineKind::Thinking
                && (l.text.starts_with('│') || l.text.starts_with('┃')))
        });
    }

    fn finish_thinking_header(&mut self) {
        if !self.thinking_open {
            return;
        }
        if let Some(line) = self.lines.iter_mut().rev().find(|l| {
            l.kind == LineKind::Thinking
                && (l.text.contains("thinking") || l.text.contains("Thought"))
                && !l.text.starts_with('│')
                && !l.text.starts_with('┃')
        }) {
            line.text = format!("Thought · done ({} chars)", self.thinking_chars);
        } else if self.thinking_chars > 0 {
            // Header missing (e.g. show_thinking off and we never opened body) — still record
            self.push_line(
                LineKind::Thinking,
                format!("Thought · done ({} chars)", self.thinking_chars),
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
        if matches!(self.view, View::Sessions(_)) {
            self.on_sessions_key(key);
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
                    self.refresh_slash_menu();
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
                    self.sync_input_scroll();
                    return;
                }
                // Grok: Ctrl+M toggles multiline when prompt focused.
                // Many terminals deliver Ctrl+M as Enter+CONTROL (CR), not Char('m').
                KeyCode::Char('m') | KeyCode::Char('M')
                    if self.pane_focus == PaneFocus::Prompt
                        || matches!(self.input_mode, InputMode::Secure { .. }) =>
                {
                    self.toggle_multiline_mode();
                    return;
                }
                KeyCode::Enter
                    if self.pane_focus == PaneFocus::Prompt
                        || matches!(self.input_mode, InputMode::Secure { .. }) =>
                {
                    self.toggle_multiline_mode();
                    return;
                }
                // Word navigation in the composer.
                KeyCode::Left
                    if self.pane_focus == PaneFocus::Prompt
                        || matches!(self.input_mode, InputMode::Secure { .. }) =>
                {
                    self.input_word_left();
                    return;
                }
                KeyCode::Right
                    if self.pane_focus == PaneFocus::Prompt
                        || matches!(self.input_mode, InputMode::Secure { .. }) =>
                {
                    self.input_word_right();
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
        // Exception: Enter with non-empty input always submits (agent-tui / automation).
        if matches!(self.view, View::Chat)
            && matches!(self.input_mode, InputMode::Normal)
            && self.pane_focus == PaneFocus::Scrollback
            && !(matches!(key.code, KeyCode::Enter) && !self.input.trim().is_empty())
        {
            let shift = key.modifiers.contains(KeyModifiers::SHIFT);
            match key.code {
                KeyCode::Esc => {
                    // Grok: mid-turn Esc cancels even from scrollback; idle Esc → prompt.
                    if self.turn_busy() {
                        self.request_cancel_turn();
                    } else if self.selection.is_some() {
                        self.selection = None;
                        self.set_flash("Selection cleared");
                    } else {
                        self.focus_prompt();
                    }
                    return;
                }
                KeyCode::Char(' ') => {
                    // Grok simple mode: Space focuses prompt (does not insert).
                    self.focus_prompt();
                    return;
                }
                // Grok Ctrl+K / Ctrl+J — one visual line (before bare j/k selection).
                KeyCode::Char('k') | KeyCode::Char('K')
                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    self.scroll_chat(1);
                    return;
                }
                KeyCode::Char('j') | KeyCode::Char('J')
                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    self.scroll_chat(-1);
                    return;
                }
                KeyCode::Char('u') | KeyCode::Char('U')
                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    self.scroll_chat_half_page(true);
                    return;
                }
                KeyCode::Char('d') | KeyCode::Char('D')
                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    self.scroll_chat_half_page(false);
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
                // Grok: Page = full viewport of visual rows; Ctrl+U/D = half page.
                KeyCode::PageUp => {
                    self.scroll_chat_page(true);
                    return;
                }
                KeyCode::PageDown => {
                    self.scroll_chat_page(false);
                    return;
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    if let Some(&first) = self.block_starts().first() {
                        if shift {
                            self.move_selection(-(self.block_starts().len() as i32), true);
                        } else {
                            self.select_block_at(first);
                        }
                    }
                    return;
                }
                KeyCode::End | KeyCode::Char('G') => {
                    if let Some(&last) = self.block_starts().last() {
                        if shift {
                            self.move_selection(self.block_starts().len() as i32, true);
                        } else {
                            self.select_block_at(last);
                        }
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
                    enum SecureSubmit {
                        Ok {
                            bulk_or_single: BulkOrSingle,
                            auth_clone: oscar_core::AuthRequest,
                            done: bool,
                        },
                        Reject(String),
                    }
                    let submit = {
                        let InputMode::Secure {
                            auth,
                            kind_index,
                            buffer,
                        } = &mut self.input_mode
                        else {
                            return;
                        };
                        let secret = std::mem::take(buffer);
                        let auth_clone = auth.clone();
                        // Bulk paste: full `export AWS_ACCESS_KEY_ID=…` (+ secret + session token).
                        let parsed = oscar_identity::parse_aws_env_exports(&secret);
                        if parsed.len() >= 2 {
                            *kind_index = auth.kinds.len();
                            SecureSubmit::Ok {
                                bulk_or_single: BulkOrSingle::Bulk(parsed),
                                auth_clone,
                                done: true,
                            }
                        } else if oscar_identity::looks_like_transcript_not_secret(&secret)
                            || (secret.lines().count() > 3 && secret.contains("AWS_"))
                        {
                            *buffer = secret;
                            SecureSubmit::Reject(
                                "Paste rejected — looks like chat or a multi-line dump. Paste only export AWS_* lines.".into(),
                            )
                        } else {
                            let kind = auth.kinds.get(*kind_index).copied();
                            let Some(kind) = kind else {
                                *buffer = secret;
                                return;
                            };
                            if matches!(
                                kind,
                                oscar_core::SecretKind::AccessKeyId
                                    | oscar_core::SecretKind::SecretAccessKey
                                    | oscar_core::SecretKind::SessionToken
                            ) {
                                if let Err(e) =
                                    oscar_identity::validate_aws_secret_value(kind, &secret)
                                {
                                    *buffer = secret;
                                    SecureSubmit::Reject(format!("Paste rejected: {e}"))
                                } else {
                                    let next = *kind_index + 1;
                                    let done = next >= auth.kinds.len();
                                    if !done {
                                        *kind_index = next;
                                    }
                                    SecureSubmit::Ok {
                                        bulk_or_single: BulkOrSingle::Single(kind, secret),
                                        auth_clone,
                                        done,
                                    }
                                }
                            } else {
                                let next = *kind_index + 1;
                                let done = next >= auth.kinds.len();
                                if !done {
                                    *kind_index = next;
                                }
                                SecureSubmit::Ok {
                                    bulk_or_single: BulkOrSingle::Single(kind, secret),
                                    auth_clone,
                                    done,
                                }
                            }
                        }
                    };
                    let SecureSubmit::Ok {
                        bulk_or_single,
                        auth_clone,
                        done,
                    } = submit
                    else {
                        if let SecureSubmit::Reject(msg) = submit {
                            self.copy_flash = Some(msg);
                        }
                        return;
                    };
                    // Optimistically unlock chat when this is an LLM provider API key paste.
                    // Host still persists AuthStore + rebuilds agent; errors surface as notices.
                    if done {
                        if let Some(hint) = auth_clone.profile_hint.as_deref() {
                            if let Some(pid) = hint.strip_prefix("provider:") {
                                self.mark_provider_ready(pid, None);
                                self.config.provider_ready = true;
                                if matches!(self.view, View::Provider(_)) {
                                    self.view = View::Chat;
                                }
                                self.push_line(
                                    LineKind::Notice,
                                    format!(
                                        "API key accepted for `{pid}` — enabling chat (agent builds in background)…"
                                    ),
                                );
                            }
                        }
                        self.input_mode = InputMode::Normal;
                    }
                    match bulk_or_single {
                        BulkOrSingle::Single(kind, secret) => {
                            self.pending_secret_batch =
                                Some((auth_clone, vec![(kind, secret)]));
                        }
                        BulkOrSingle::Bulk(fields) => {
                            self.push_line(
                                LineKind::Notice,
                                format!(
                                    "Bulk AWS credential paste detected ({} field(s)) — storing to oscar secrets (values never shown to agent)…",
                                    fields.len()
                                ),
                            );
                            // One batch → one host store+resume (do not split fields).
                            self.pending_secret_batch = Some((auth_clone, fields));
                        }
                    }
                    self.input_cursor = 0;
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
                    // Grok: clear draft → cancel → double-press quit (never instant quit).
                    self.handle_ctrl_c_chat();
                }
                KeyCode::Char(',') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.open_settings();
                }
                KeyCode::Char('i') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.open_identities();
                }
                KeyCode::Esc => {
                    self.handle_esc_chat();
                }
                KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.show_thinking = !self.show_thinking;
                    self.config.oscar_config.ui.show_thinking = self.show_thinking;
                    self.refresh_status();
                }
                // Chat scroll while prompt focused (Grok: continuous visual rows).
                KeyCode::PageUp => {
                    self.scroll_chat_page(true);
                }
                KeyCode::PageDown => {
                    self.scroll_chat_page(false);
                }
                KeyCode::Char('u') | KeyCode::Char('U')
                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    self.scroll_chat_half_page(true);
                }
                KeyCode::Char('d') | KeyCode::Char('D')
                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    self.scroll_chat_half_page(false);
                }
                KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.scroll_chat(1);
                }
                KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.scroll_chat(-1);
                }
                // Up/Down: visual lines in multi-row composer; empty → scrollback.
                KeyCode::Up
                    if self.slash_menu.is_none()
                        && !key.modifiers.contains(KeyModifiers::SHIFT)
                        && !key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    if self.input.is_empty() {
                        self.focus_scrollback();
                        self.move_selection(-1, false);
                    } else {
                        let rows = self.input_rows();
                        let text_len = Self::input_char_len(&self.input);
                        let (r, _) = cursor_row_col(&rows, self.input_cursor, text_len);
                        if r > 0 {
                            self.input_move_visual(-1);
                        }
                        // at top row with text: stay in composer (Grok)
                    }
                }
                KeyCode::Down
                    if self.slash_menu.is_none()
                        && !key.modifiers.contains(KeyModifiers::SHIFT)
                        && !key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    if self.input.is_empty() {
                        self.focus_scrollback();
                        self.move_selection(1, false);
                    } else {
                        let rows = self.input_rows();
                        let text_len = Self::input_char_len(&self.input);
                        let (r, _) = cursor_row_col(&rows, self.input_cursor, text_len);
                        if r + 1 < rows.len() {
                            self.input_move_visual(1);
                        }
                    }
                }
                KeyCode::Home if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    // Furthest allowed back (cutoff), not infinite history
                    self.chat_scroll = self.max_chat_scroll();
                    self.stick_to_bottom = self.chat_scroll == 0;
                }
                KeyCode::Home => self.input_line_home(),
                KeyCode::End if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.pin_to_bottom();
                }
                KeyCode::End => {
                    self.input_line_end();
                }
                KeyCode::Left if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if self.input_cursor > 0 {
                        self.input_cursor -= 1;
                    }
                    self.sync_input_scroll();
                }
                KeyCode::Right if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.input_cursor = self.input_cursor.saturating_add(1);
                    self.clamp_cursor();
                    self.sync_input_scroll();
                }
                KeyCode::Delete => {
                    self.focus_prompt();
                    self.input_delete_forward();
                    self.refresh_slash_menu();
                    self.sync_input_scroll();
                }
                // Shift+Enter / Alt+Enter → newline (or send in multiline mode).
                // Some terminals deliver newline as Char('\n') / '\r'.
                KeyCode::Char('\n') | KeyCode::Char('\r') => {
                    if self.enter_inserts_newline(key) {
                        self.focus_prompt();
                        self.input_insert_newline();
                        self.refresh_slash_menu();
                    } else {
                        // Treat as submit — fall through by synthesizing Enter path
                        self.focus_prompt();
                        self.submit_composer();
                    }
                }
                KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    // Ctrl+M / Ctrl+Enter → multiline toggle (see global Ctrl chords too).
                    self.toggle_multiline_mode();
                }
                KeyCode::Enter => {
                    // Always own the prompt on submit (agent-tui / paste can leave
                    // focus on scrollback where Enter only copies selection).
                    self.focus_prompt();
                    if self.enter_inserts_newline(key) {
                        self.input_insert_newline();
                        self.refresh_slash_menu();
                        return;
                    }
                    self.submit_composer();
                }
                KeyCode::Backspace => {
                    self.focus_prompt();
                    self.input_backspace();
                    self.refresh_slash_menu();
                }
                // Slash menu navigation takes priority over chat scroll / empty-input focus.
                KeyCode::Up if self.slash_menu.is_some() => {
                    if let Some(m) = self.slash_menu.as_mut() {
                        m.move_sel(-1);
                    }
                }
                KeyCode::Down if self.slash_menu.is_some() => {
                    if let Some(m) = self.slash_menu.as_mut() {
                        m.move_sel(1);
                    }
                }
                KeyCode::Tab if self.slash_menu.is_some() => {
                    if let Some(menu) = self.slash_menu.clone() {
                        if let Some(filled) = menu.apply_to_input() {
                            self.input = filled;
                            self.input_cursor = self.input.chars().count();
                            self.refresh_slash_menu();
                        }
                    }
                }
                KeyCode::Char(c)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && c != '\n'
                        && c != '\r' =>
                {
                    self.focus_prompt();
                    self.input_insert_char(c);
                    // `/` alone or `/…` immediately opens / refilters the command menu.
                    self.refresh_slash_menu();
                }
                _ => {}
            },
        }
    }

    /// Submit the current composer buffer (Enter / Shift+Enter in multiline).
    fn submit_composer(&mut self) {
        // Slash menu completion rules:
        // - Input already has args (`/model list`) → submit as typed.
        // - Menu open, no args, command needs no usage → complete + run.
        // - Menu open, no args, command needs usage → complete to `/name `
        //   and if user hits Enter again on bare `/name` or `/name `,
        //   run the command (list default) instead of no-op.
        let trimmed_in = self.input.trim().to_string();
        let has_args = trimmed_in.starts_with('/')
            && trimmed_in.len() > 1
            && trimmed_in[1..].contains(' ');
        if has_args {
            self.slash_menu = None;
        } else if let Some(menu) = self.slash_menu.clone() {
            if let Some(filled) = menu.apply_to_input() {
                let cmd = menu.selected_cmd();
                let needs_args = cmd.map(|c| !c.usage.is_empty()).unwrap_or(false);
                // Bare `/model` (or `/model `) with usage → treat as list.
                let bare = trimmed_in.starts_with('/')
                    && trimmed_in.len() > 1
                    && !trimmed_in[1..].contains(' ');
                if needs_args && bare {
                    self.input = trimmed_in;
                    self.input_cursor = self.input.chars().count();
                    self.slash_menu = None;
                    // fall through → host runs `/model` as list
                } else if needs_args {
                    self.input = filled;
                    self.input_cursor = self.input.chars().count();
                    self.slash_menu = None;
                    self.refresh_slash_menu();
                    return;
                } else {
                    self.input = filled;
                    self.input_cursor = self.input.chars().count();
                    self.slash_menu = None;
                    // fall through to run no-arg commands
                }
            }
        }
        // Preserve intentional newlines in the payload; only trim ends.
        let line = self.input.trim().to_string();
        if line.is_empty() {
            return;
        }
        if line == "/" {
            // Keep menu open for bare slash
            self.refresh_slash_menu();
            return;
        }
        let is_cmd = is_slash_command(&line) || line.starts_with('/');
        // While a model turn is running, queue chat (not slash cmds).
        // Grok Build / OpenCode pattern: type ahead, send on Done.
        if self.turn_busy() && !is_cmd {
            if !self.config.provider_ready {
                self.open_provider_setup(
                    "LLM provider not ready — set one up before chatting.",
                );
                return;
            }
            self.input.clear();
            self.input_cursor = 0;
            self.input_scroll = 0;
            self.slash_menu = None;
            self.prompt_queue.push_back(line.clone());
            let n = self.prompt_queue.len();
            let preview: String = line.chars().take(60).collect();
            let ellipsis = if line.chars().count() > 60 { "…" } else { "" };
            self.set_flash(format!("queued #{n}: {preview}{ellipsis}"));
            self.push_line(
                LineKind::Notice,
                format!("queued #{n}: {preview}{ellipsis}"),
            );
            return;
        }
        if self.turn_busy() && is_cmd {
            // Slash commands wait until idle (except /quit).
            if !matches!(line.as_str(), "/quit" | "/exit") {
                self.set_flash("wait for turn (or Esc cancel) before slash cmds");
                return;
            }
        }
        if !self.config.provider_ready && !is_cmd && !line.starts_with('/') {
            // Chat needs an LLM — open provider setup instead of failing later.
            self.open_provider_setup("LLM provider not ready — set one up before chatting.");
            return;
        }
        self.input.clear();
        self.input_cursor = 0;
        self.input_scroll = 0;
        self.slash_menu = None;
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
        // Grok Build: bare /resume opens the session picker (no args).
        if matches!(
            line.as_str(),
            "/resume" | "/history" | "/sessions" | "/session"
        ) {
            self.open_sessions_picker();
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
                LineKind::Notice,
                "/model · /provider · /connect · /settings · /identities · /skills · /mcp · /thinking · /context · /compact · /resume · /new · /copy · /quit",
            );
            self.push_line(
                LineKind::Notice,
                "/model list  ·  /model 2  ·  /model grok-4  ·  /model openai/gpt-4o  (multi-provider)",
            );
            self.push_line(
                LineKind::Notice,
                "Type / to open the command menu · Tab = chat↔input · Shift/Alt+Enter newline · Ctrl+M or /multiline · y copy · Ctrl+V paste",
            );
            return;
        }
        // Grok parity: toggle multiline composer (also Ctrl+M when terminal reports it).
        if matches!(
            line.as_str(),
            "/multiline" | "/multiline toggle" | "/ml"
        ) {
            self.toggle_multiline_mode();
            return;
        }
        if line == "/multiline on" {
            if !self.multiline_mode {
                self.toggle_multiline_mode();
            } else {
                self.set_flash("multiline already ON");
            }
            return;
        }
        if line == "/multiline off" {
            if self.multiline_mode {
                self.toggle_multiline_mode();
            } else {
                self.set_flash("multiline already OFF");
            }
            return;
        }
        // /copy is local (clipboard) — don't send to host/model
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
            if rest.eq_ignore_ascii_case("all") {
                self.copy_full_chat();
                return;
            }
            if let Ok(n) = rest.parse::<usize>() {
                self.copy_nth_assistant(n);
                return;
            }
            if let Some(text) = self.selection_text() {
                match std::fs::write(rest, &text) {
                    Ok(()) => self.push_line(
                        LineKind::Notice,
                        format!("Wrote {} bytes → {rest}", text.len()),
                    ),
                    Err(e) => self.push_line(LineKind::Error, format!("Write failed: {e}")),
                }
            } else {
                self.push_line(LineKind::Notice, "Nothing to copy.");
            }
            return;
        }
        // All other slash commands → host (never as a model chat turn)
        if is_cmd || line.starts_with('/') {
            self.push_line(LineKind::Notice, format!("→ {line}"));
            self.awaiting_reply = false;
            self.streaming = false;
            self.pending_user = Some(line);
            return;
        }
        // Normal chat turn
        self.push_line(LineKind::User, line.clone());
        self.awaiting_reply = true;
        self.pending_user = Some(line);
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

    /// Handle one-shot settings actions (e.g. jump to Provider UI).
    fn handle_settings_action(&mut self) {
        use crate::settings::SettingsAction;
        let action = match &mut self.view {
            View::Settings(pane) => pane.take_action(),
            _ => None,
        };
        match action {
            Some(SettingsAction::OpenProviderPane) => {
                self.close_settings(true);
                self.open_provider_setup("Provider setup");
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

    fn on_sessions_key(&mut self, key: crossterm::event::KeyEvent) {
        let View::Sessions(ref mut pane) = self.view else {
            return;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') if key.modifiers.is_empty() => {
                self.close_sessions_picker();
            }
            KeyCode::Up | KeyCode::Char('k') => pane.move_list(-1),
            KeyCode::Down | KeyCode::Char('j') => pane.move_list(1),
            KeyCode::Home => {
                pane.list_idx = 0;
            }
            KeyCode::End => {
                if !pane.filtered.is_empty() {
                    pane.list_idx = pane.filtered.len() - 1;
                }
            }
            KeyCode::PageUp => pane.move_list(-10),
            KeyCode::PageDown => pane.move_list(10),
            KeyCode::Enter => {
                pane.activate();
                self.dispatch_sessions_pending();
            }
            KeyCode::Backspace => pane.filter_backspace(),
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                pane.clear_filter();
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                pane.push_filter_char(c);
            }
            _ => {}
        }
    }

    fn dispatch_sessions_pending(&mut self) {
        let pending = match &mut self.view {
            View::Sessions(p) => p.take_pending(),
            _ => None,
        };
        match pending {
            Some(SessionsPaneAction::Resume { id }) => {
                self.view = View::Chat;
                self.push_line(
                    LineKind::Notice,
                    format!("Resuming session `{}`…", &id[..id.len().min(8)]),
                );
                // Host loads agent history + transcript
                self.pending_user = Some(format!("/resume {id}"));
            }
            Some(SessionsPaneAction::Close) | None => {
                self.close_sessions_picker();
            }
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

/// Session identity when the TUI exits (for the post-exit resume hint).
#[derive(Debug, Clone)]
pub struct TuiExit {
    pub session_id: String,
    pub session_title: String,
}

impl TuiExit {
    /// Print how to reopen this chat. Safe after `LeaveAlternateScreen`.
    pub fn print_resume_hint(&self) {
        use std::io::Write;
        let id = self.session_id.trim();
        // Always write to stderr so the shell still shows it if stdout is redirected.
        let mut err = std::io::stderr();
        let _ = writeln!(err);
        if id.is_empty() {
            let _ = writeln!(err, "Session ended");
            let _ = err.flush();
            return;
        }
        let _ = writeln!(err, "Session ended");
        let _ = writeln!(err, "oscar sessions resume {id}");
        let _ = writeln!(err);
        let _ = err.flush();
    }
}

pub async fn run_tui(
    mut app: App,
    mut events: mpsc::Receiver<AgentEvent>,
    user_tx: mpsc::UnboundedSender<String>,
    secret_tx: mpsc::Sender<(
        AuthRequest,
        Vec<(oscar_core::SecretKind, String)>,
    )>,
    cancel_tx: mpsc::Sender<()>,
    config_tx: mpsc::Sender<OscarConfig>,
    mut session_rx: mpsc::Receiver<oscar_core::StoredChatSession>,
    transcript_tx: mpsc::Sender<Vec<TranscriptLine>>,
) -> io::Result<TuiExit> {
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

    // Best-effort cancel so the host does not hang mid-turn on quit.
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
    let _ = cancel_tx.try_send(());

    let exit = TuiExit {
        session_id: app.session_id.clone(),
        session_title: app.session_title.clone(),
    };

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        DisableBracketedPaste,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    // Print resume hint immediately after leaving the alt screen (before host
    // join), so a normal /quit or double-Ctrl+C always shows how to return.
    // Use stderr + flush — stdout can still be tied up with leftover TUI state.
    exit.print_resume_hint();
    result?;
    Ok(exit)
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    events: &mut mpsc::Receiver<AgentEvent>,
    user_tx: &mpsc::UnboundedSender<String>,
    secret_tx: &mpsc::Sender<(
        AuthRequest,
        Vec<(oscar_core::SecretKind, String)>,
    )>,
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

        // Session loads first so a bootstrap re-push cannot race and wipe events
        // processed earlier in the same tick (see load_transcript same-session guard).
        while let Ok(s) = session_rx.try_recv() {
            let switching = !app.session_id.is_empty() && app.session_id != s.id;
            app.load_transcript(&s.transcript, &s.id, &s.title);
            if switching {
                app.push_line(
                    LineKind::System,
                    format!(
                        "Loaded chat «{}» ({}) · /new · /resume",
                        s.title,
                        &s.id[..s.id.len().min(8)]
                    ),
                );
            }
        }

        while let Ok(ev) = events.try_recv() {
            app.handle_agent_event(ev);
        }
        app.tick_flash();
        app.activity_tick = app.activity_tick.wrapping_add(1);

        if let Some(batch) = app.pending_secret_batch.take() {
            let _ = secret_tx.send(batch).await;
        }
        if let Some(user) = app.pending_user.take() {
            let is_cmd = user.trim().starts_with('/');
            // Never stream chat turns when no provider — avoids stuck cancel/streaming bug.
            if !app.config.provider_ready && !is_cmd {
                app.streaming = false;
                app.awaiting_reply = false;
                app.open_provider_setup(
                    "Chat blocked: no LLM provider ready. Sign in / paste a key first.",
                );
            } else {
                // Slash commands never enter "awaiting model reply" / streaming UI.
                if is_cmd {
                    app.awaiting_reply = false;
                    app.streaming = false;
                } else {
                    app.awaiting_reply = true;
                    app.streaming = true;
                }
                if user_tx.send(user).is_err() {
                    app.push_line(
                        LineKind::Error,
                        "Internal error: chat host is not running (message not delivered).",
                    );
                    app.streaming = false;
                    app.awaiting_reply = false;
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

        // Drain all pending input without blocking the async runtime, then
        // yield so the chat host / SSE tasks can run. Blocking `event::poll(50ms)`
        // on a tokio worker starved the host: TUI `user_tx.send` succeeded but
        // `user_rx.recv` never ran (SSE-only prompts still worked when idle).
        while event::poll(Duration::from_millis(0))? {
            match event::read()? {
                Event::Key(key) => app.on_key(key),
                Event::Mouse(m) => app.on_mouse(m),
                Event::Paste(text) => app.on_paste_event(text),
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(16)).await;
    }
    Ok(())
}

/// Pull provider id from host notices like:
/// `[secure bar] stored API key for provider \`xai\` …`
/// `[provider ready: grok — you can chat now]`
fn extract_provider_id_from_notice(text: &str) -> Option<String> {
    if let Some(rest) = text.split("for provider `").nth(1) {
        if let Some(pid) = rest.split('`').next() {
            let pid = pid.trim();
            if !pid.is_empty() {
                return Some(pid.to_string());
            }
        }
    }
    if let Some(rest) = text.split("[provider ready:").nth(1) {
        let rest = rest.trim_start();
        let pid: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .collect();
        if !pid.is_empty() {
            return Some(pid);
        }
    }
    None
}

/// `[active profile: aws-default]` / `[active profile: —]`
fn extract_active_profile_from_notice(text: &str) -> Option<String> {
    let rest = text.split("[active profile:").nth(1)?;
    let rest = rest.trim_start();
    let end = rest.find(']').unwrap_or(rest.len());
    let pid = rest[..end].trim();
    if pid.is_empty() {
        None
    } else {
        Some(pid.to_string())
    }
}

/// `[model] grok/grok-4 → grok/grok-4.5  (loaded providers kept; /model list)`
fn extract_model_switch_from_notice(text: &str) -> Option<(String, String)> {
    let rest = text.split("[model]").nth(1)?;
    // Prefer the arrow target: "… → provider/model"
    let target = rest.split('→').nth(1).unwrap_or(rest);
    let token = target
        .split_whitespace()
        .next()?
        .trim_matches(|c: char| c == '(' || c == ')' || c == ',' || c == ';');
    let (p, m) = token.split_once('/')?;
    let p = p.trim();
    let m = m.trim();
    if p.is_empty() || m.is_empty() {
        None
    } else {
        Some((p.to_string(), m.to_string()))
    }
}

#[cfg(test)]
mod extract_pid_tests {
    use super::{
        extract_active_profile_from_notice, extract_model_switch_from_notice,
        extract_provider_id_from_notice, App,
    };

    #[test]
    fn from_secure_bar_notice() {
        let t = "\n[secure bar] stored API key for provider `xai` (84 bytes) — value NOT visible to agent. Building agent…\n";
        assert_eq!(
            extract_provider_id_from_notice(t).as_deref(),
            Some("xai")
        );
    }

    #[test]
    fn from_provider_ready_notice() {
        let t = "\n[provider ready: grok — you can chat now]\n";
        assert_eq!(
            extract_provider_id_from_notice(t).as_deref(),
            Some("grok")
        );
    }

    #[test]
    fn active_profile_notice() {
        assert_eq!(
            extract_active_profile_from_notice("\n[active profile: aws-default]\n").as_deref(),
            Some("aws-default")
        );
        assert_eq!(
            extract_active_profile_from_notice("[active profile: —]").as_deref(),
            Some("—")
        );
    }

    #[test]
    fn model_switch_notice() {
        let t = "\n[model] grok/grok-4 → grok/grok-4.5  (loaded providers kept; /model list)\n";
        assert_eq!(
            extract_model_switch_from_notice(t),
            Some(("grok".into(), "grok-4.5".into()))
        );
    }

    #[test]
    fn profile_status_is_capped() {
        let long = "a".repeat(40);
        let shown = App::format_status_profile(Some(&long), 1);
        assert!(shown.chars().count() <= App::STATUS_PROFILE_MAX_CHARS);
        assert!(shown.ends_with('…'));
        assert_eq!(
            App::format_status_profile(Some("aws-default"), 2),
            "aws-default"
        );
        assert_eq!(App::format_status_profile(None, 0), "—");
    }

    fn test_app() -> App {
        App::new(crate::app::AppConfig {
            provider: "xai".into(),
            model: "test".into(),
            mode: oscar_core::ExecutionMode::ReadOnly,
            show_thinking: false,
            profile_count: 0,
            active_profile: None,
            oscar_config: oscar_core::OscarConfig::default(),
            tool_catalog: vec![],
            profiles_path: std::path::PathBuf::from("/tmp/oscar-test-profiles.toml"),
            provider_ready: true,
        })
    }

    #[test]
    fn block_bounds_groups_assistant_reply() {
        let mut app = test_app();
        app.lines.clear();
        app.push_line(crate::app::LineKind::User, "hi");
        app.push_line(crate::app::LineKind::Assistant, "line one of a long answer");
        app.push_line(crate::app::LineKind::Assistant, "line two still same block");
        app.push_line(crate::app::LineKind::Assistant, "line three");
        app.push_line(crate::app::LineKind::Tool, "◆ tools_search");
        // indices: 0 user, 1-3 assistant, 4 tool
        assert_eq!(app.block_bounds(2), (1, 3));
        assert_eq!(app.block_bounds(0), (0, 0));
        assert_eq!(app.block_bounds(4), (4, 4));
        app.select_block_at(2);
        let sel = app.selection.unwrap();
        assert_eq!(sel.range(), (1, 3));
        let text = app.selection_text().unwrap();
        assert!(text.contains("line one"));
        assert!(text.contains("line three"));
        assert!(!text.contains("assistant:"), "no role prefixes: {text}");
    }

    #[test]
    fn copy_nth_assistant_is_plain_body() {
        let mut app = test_app();
        app.lines.clear();
        app.push_line(crate::app::LineKind::Assistant, "first reply");
        app.push_line(crate::app::LineKind::User, "again");
        app.push_line(crate::app::LineKind::Assistant, "second A");
        app.push_line(crate::app::LineKind::Assistant, "second B");
        assert_eq!(
            app.nth_assistant_text(1).as_deref(),
            Some("second A\nsecond B")
        );
        assert_eq!(app.nth_assistant_text(2).as_deref(), Some("first reply"));
    }

    #[test]
    fn esc_does_not_quit_when_idle() {
        let mut app = test_app();
        app.should_quit = false;
        app.handle_esc_chat();
        assert!(!app.should_quit);
    }

    #[test]
    fn esc_cancels_busy_turn() {
        let mut app = test_app();
        app.streaming = true;
        app.awaiting_reply = true;
        app.handle_esc_chat();
        assert!(app.cancel_requested);
        assert!(!app.streaming);
        assert!(!app.awaiting_reply);
        assert!(!app.should_quit);
    }

    #[test]
    fn esc_esc_clears_prompt() {
        let mut app = test_app();
        app.input = "hello".into();
        app.input_cursor = 5;
        app.pane_focus = crate::app::PaneFocus::Prompt;
        app.handle_esc_chat();
        assert_eq!(app.input, "hello");
        assert!(app.esc_clear_armed_at.is_some());
        app.handle_esc_chat();
        assert!(app.input.is_empty());
        assert!(!app.should_quit);
    }

    #[test]
    fn ctrl_c_clear_then_arm_quit() {
        let mut app = test_app();
        app.input = "draft".into();
        app.handle_ctrl_c_chat();
        assert!(app.input.is_empty());
        assert!(!app.should_quit);
        app.handle_ctrl_c_chat();
        assert!(app.ctrl_c_quit_armed_at.is_some());
        assert!(!app.should_quit);
        app.handle_ctrl_c_chat();
        assert!(app.should_quit);
    }

    #[test]
    fn turn_busy_queues_not_only_streaming_flag() {
        let mut app = test_app();
        app.awaiting_reply = true;
        app.streaming = false;
        assert!(app.turn_busy());
    }

    #[test]
    fn text_selection_copies_char_range_not_whole_block() {
        use super::{LineKind, LineSelection, TextPos, TextSelection};
        let mut app = test_app();
        app.lines.clear();
        app.push_line(LineKind::Assistant, "Hello world from oscar");
        // Select only "world" (chars 6..11 in "Hello world from oscar")
        app.text_selection = Some(TextSelection {
            anchor: TextPos {
                line_idx: 0,
                char_off: 6,
            },
            head: TextPos {
                line_idx: 0,
                char_off: 11,
            },
        });
        let t = app.text_selection_string().expect("has text");
        assert_eq!(t, "world");
        app.selection = Some(LineSelection::single(0));
        let block = app.selection_text().unwrap();
        assert!(block.contains("Hello world"));
        assert_ne!(t, block);
    }
}
