use crate::identities::IdentitiesPane;
use crate::input::{IdleHintRotator, InputMode};
use crate::settings::{SettingsPane, ToolCatalogEntry};
use crate::ui;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
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
}

pub struct App {
    pub config: AppConfig,
    pub lines: Vec<ChatLine>,
    pub input: String,
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
            thinking_open: false,
            thinking_chars: 0,
        };
        app.trim_transcript();
        app.pin_to_bottom();
        app.refresh_status();
        app
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
        self.refresh_status();
    }

    pub fn handle_agent_event(&mut self, ev: AgentEvent) {
        match ev {
            AgentEvent::ContentDelta { text } => {
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
                    "After auth, oscar auto-retries the paused tool.",
                );
                if auth.kinds.is_empty() {
                    self.push_line(
                        LineKind::System,
                        "No secret fields to paste — run the hint command (e.g. aws sso login), then send any message or wait for resume.",
                    );
                } else {
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
                self.push_line(LineKind::Error, message);
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
        if matches!(self.view, View::Identities(_)) {
            self.on_identities_key(key);
            return;
        }

        if self.streaming
            && (key.code == KeyCode::Esc
                || (key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('c')))
        {
            self.cancel_requested = true;
            self.push_line(LineKind::System, "Cancel requested…");
            return;
        }

        match &mut self.input_mode {
            InputMode::Secure {
                auth,
                kind_index,
                buffer,
            } => match key.code {
                KeyCode::Esc => {
                    self.input_mode = InputMode::Normal;
                    self.push_line(LineKind::System, "Credential entry cancelled.");
                }
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Enter => {
                    if buffer.is_empty() {
                        return;
                    }
                    let kind = auth.kinds.get(*kind_index).copied();
                    if let Some(kind) = kind {
                        let secret = std::mem::take(buffer);
                        let auth_clone = auth.clone();
                        let next = *kind_index + 1;
                        if next < auth.kinds.len() {
                            *kind_index = next;
                            self.pending_secret = Some((auth_clone, kind, secret));
                        } else {
                            self.pending_secret = Some((auth_clone, kind, secret));
                            self.input_mode = InputMode::Normal;
                        }
                    }
                }
                KeyCode::Char(c) => {
                    buffer.push(c);
                }
                _ => {}
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
                    self.should_quit = true;
                }
                KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.show_thinking = !self.show_thinking;
                    self.config.oscar_config.ui.show_thinking = self.show_thinking;
                    self.refresh_status();
                }
                // Chat scroll: PageUp/Up = older · PageDown/Down/End = newer · End pins bottom
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
                KeyCode::Home if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    // Furthest allowed back (cutoff), not infinite history
                    self.chat_scroll = self.max_chat_scroll();
                    self.stick_to_bottom = self.chat_scroll == 0;
                }
                KeyCode::End => {
                    self.pin_to_bottom();
                }
                KeyCode::Enter => {
                    let line = self.input.trim().to_string();
                    if line.is_empty() || self.streaming {
                        return;
                    }
                    self.input.clear();
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
                        "/identities" | "/identity" | "/access" | "/whoami"
                    ) {
                        self.open_identities();
                        return;
                    }
                    if line == "/help" {
                        self.push_line(
                            LineKind::System,
                            "/settings · /identities · /skills · /mcp · /thinking · /context · /compact · /history · /new · /resume · /quit",
                        );
                        self.push_line(
                            LineKind::System,
                            "Chat history auto-saves · /history lists sessions · /new fresh chat · /resume <id>",
                        );
                        self.push_line(
                            LineKind::System,
                            "Settings Ctrl+, · Identities Ctrl+I · approve install | deny install",
                        );
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
                    self.input.pop();
                }
                KeyCode::Char(c) => {
                    self.input.push(c);
                }
                _ => {}
            },
        }
    }

    fn on_settings_key(&mut self, key: crossterm::event::KeyEvent) {
        let View::Settings(ref mut pane) = self.view else {
            return;
        };

        match key.code {
            KeyCode::Esc => {
                // save by default (Grok-like: leave persists)
                self.close_settings(true);
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
            KeyCode::Left | KeyCode::Char('h') => {
                pane.move_category(-1);
            }
            KeyCode::Right | KeyCode::Char('l') => {
                pane.move_category(1);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                pane.move_item(-1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                pane.move_item(1);
            }
            KeyCode::Tab => {
                pane.move_category(1);
            }
            KeyCode::BackTab => {
                pane.move_category(-1);
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                pane.activate();
            }
            KeyCode::Char('[') => {
                pane.activate_back();
            }
            KeyCode::Char(']') => {
                pane.activate();
            }
            KeyCode::PageUp => {
                for _ in 0..10 {
                    pane.move_item(-1);
                }
            }
            KeyCode::PageDown => {
                for _ in 0..10 {
                    pane.move_item(1);
                }
            }
            KeyCode::Home => {
                pane.item_idx = 0;
            }
            KeyCode::End => {
                let n = pane.items().len();
                if n > 0 {
                    pane.item_idx = n - 1;
                }
            }
            // number keys jump categories 1-8
            KeyCode::Char(c @ '1'..='8') => {
                let idx = (c as u8 - b'1') as usize;
                if idx < crate::settings::SettingsCategory::ALL.len() {
                    pane.category_idx = idx;
                    pane.item_idx = 0;
                    pane.item_scroll = 0;
                    pane.flash = Some(pane.category().hint().into());
                }
            }
            KeyCode::Char('i') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                // Jump from settings to identities panel
                self.view = View::Chat;
                self.open_identities();
                return;
            }
            _ => {}
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
    execute!(stdout, EnterAlternateScreen)?;
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
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
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
            let _ = user_tx.send(user).await;
            // Don't mark streaming for pure slash history commands (host will Done quickly)
            if !is_history_cmd {
                app.streaming = true;
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
            if let Event::Key(key) = event::read()? {
                app.on_key(key);
            }
        }
    }
    Ok(())
}
