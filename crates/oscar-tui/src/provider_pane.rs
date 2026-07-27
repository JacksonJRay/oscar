//! Dedicated LLM provider setup UI — list providers, set default, auth, edit model/URL.
//!
//! Auth model (all use API keys after account access where needed):
//! - **xAI / OpenCode Zen/Go**: open console in browser → create/copy key → paste securely
//! - **OpenAI / Anthropic**: open API keys page → paste key
//! - **Custom**: set id + base_url + paste key

use oscar_core::config::{OscarConfig, ProviderSettings};
use oscar_identity::load_provider_api_key;

/// Built-in providers shown in the picker (Grok primary).
pub const BUILTIN_PROVIDERS: &[ProviderMeta] = &[
    ProviderMeta {
        id: "grok",
        name: "Grok (xAI) ★ primary",
        auth_hint: "oscar auth login (OAuth) · or console.x.ai API key",
        console_url: "https://console.x.ai/team/default/api-keys",
        default_base: "https://api.x.ai/v1",
        default_model: "grok-4",
        needs_account: true,
    },
    ProviderMeta {
        id: "xai",
        name: "xAI (alias of Grok)",
        auth_hint: "Same as Grok — OAuth or API key (shared keychain)",
        console_url: "https://console.x.ai/team/default/api-keys",
        default_base: "https://api.x.ai/v1",
        default_model: "grok-4",
        needs_account: true,
    },
    ProviderMeta {
        id: "openai",
        name: "OpenAI",
        auth_hint: "platform.openai.com → API keys → paste sk-… key",
        console_url: "https://platform.openai.com/api-keys",
        default_base: "https://api.openai.com/v1",
        default_model: "gpt-4.1",
        needs_account: false,
    },
    ProviderMeta {
        id: "anthropic",
        name: "Anthropic (Claude)",
        auth_hint: "console.anthropic.com → API keys → paste key",
        console_url: "https://console.anthropic.com/settings/keys",
        default_base: "https://api.anthropic.com",
        default_model: "claude-sonnet-4-5",
        needs_account: false,
    },
    ProviderMeta {
        id: "opencode-zen",
        name: "OpenCode Zen",
        auth_hint: "Sign in at opencode.ai/auth → copy Zen API key → paste",
        console_url: "https://opencode.ai/auth",
        default_base: "https://opencode.ai/zen/v1",
        default_model: "default",
        needs_account: true,
    },
    ProviderMeta {
        id: "opencode-go",
        name: "OpenCode Go",
        auth_hint: "Sign in at opencode.ai/auth → subscribe Go → copy key → paste",
        console_url: "https://opencode.ai/auth",
        default_base: "https://opencode.ai/zen/v1",
        default_model: "default",
        needs_account: true,
    },
];

#[derive(Debug, Clone, Copy)]
pub struct ProviderMeta {
    pub id: &'static str,
    pub name: &'static str,
    pub auth_hint: &'static str,
    pub console_url: &'static str,
    pub default_base: &'static str,
    pub default_model: &'static str,
    /// True if user typically signs into a console first (xAI / OpenCode).
    pub needs_account: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFocus {
    /// Left: pick which provider row
    List,
    /// Right: actions for the selected provider
    Actions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAction {
    SetDefault,
    OpenConsole,
    PasteKey,
    EditModel,
    EditBaseUrl,
    ClearKey,
    AddCustom,
}

impl ProviderAction {
    pub fn label(self, has_key: bool, is_default: bool, needs_account: bool) -> &'static str {
        match self {
            Self::SetDefault => {
                if is_default {
                    "● Default provider"
                } else {
                    "Set as default"
                }
            }
            Self::OpenConsole => {
                if needs_account {
                    "1. Open console / sign in (browser)"
                } else {
                    "1. Open API keys page (browser)"
                }
            }
            Self::PasteKey => {
                if has_key {
                    "2. Paste / replace API key"
                } else {
                    "2. Paste API key (required)"
                }
            }
            Self::EditModel => "Edit model id",
            Self::EditBaseUrl => "Edit base URL",
            Self::ClearKey => "Clear stored key",
            Self::AddCustom => "+ Add custom OpenAI-compatible provider",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProviderEdit {
    Model { buffer: String, cursor: usize },
    BaseUrl { buffer: String, cursor: usize },
    CustomId { buffer: String, cursor: usize },
    CustomUrl { buffer: String, cursor: usize },
}

/// Request for App/host after an action.
#[derive(Debug, Clone)]
pub enum ProviderPaneAction {
    PasteApiKey { provider_id: String },
    OpenBrowser { url: String, label: String },
    /// Config changed — App should apply + save.
    ConfigChanged,
    /// Close the pane (save).
    Close,
}

#[derive(Debug, Clone)]
pub struct ProviderRow {
    pub id: String,
    pub name: String,
    pub is_builtin: bool,
    pub needs_account: bool,
    pub console_url: String,
    pub auth_hint: String,
    pub default_base: String,
    pub default_model: String,
}

pub struct ProviderPane {
    pub config: OscarConfig,
    pub rows: Vec<ProviderRow>,
    pub list_idx: usize,
    pub action_idx: usize,
    pub focus: ProviderFocus,
    pub flash: Option<String>,
    pub edit: Option<ProviderEdit>,
    pub dirty: bool,
    pub pending: Option<ProviderPaneAction>,
}

impl ProviderPane {
    pub fn open(config: OscarConfig) -> Self {
        let mut pane = Self {
            config,
            rows: vec![],
            list_idx: 0,
            action_idx: 0,
            focus: ProviderFocus::List,
            flash: Some(
                "↑↓ select provider · → actions · Enter run · ← back · Esc close · type to edit"
                    .into(),
            ),
            edit: None,
            dirty: false,
            pending: None,
        };
        pane.rebuild_rows();
        // Select current default
        if let Some(i) = pane
            .rows
            .iter()
            .position(|r| r.id == pane.config.provider.id)
        {
            pane.list_idx = i;
        }
        pane
    }

    fn rebuild_rows(&mut self) {
        let mut rows: Vec<ProviderRow> = BUILTIN_PROVIDERS
            .iter()
            .map(|m| ProviderRow {
                id: m.id.into(),
                name: m.name.into(),
                is_builtin: true,
                needs_account: m.needs_account,
                console_url: m.console_url.into(),
                auth_hint: m.auth_hint.into(),
                default_base: m.default_base.into(),
                default_model: m.default_model.into(),
            })
            .collect();

        // Custom active provider not in builtins
        let id = self.config.provider.id.as_str();
        if !BUILTIN_PROVIDERS.iter().any(|m| m.id == id) && !id.is_empty() {
            rows.push(ProviderRow {
                id: id.into(),
                name: format!("Custom ({id})"),
                is_builtin: false,
                needs_account: false,
                console_url: self
                    .config
                    .provider
                    .base_url
                    .clone()
                    .unwrap_or_else(|| "https://…".into()),
                auth_hint: "Custom OpenAI-compatible endpoint + API key".into(),
                default_base: self
                    .config
                    .provider
                    .base_url
                    .clone()
                    .unwrap_or_default(),
                default_model: self
                    .config
                    .provider
                    .model
                    .clone()
                    .unwrap_or_else(|| "default".into()),
            });
        }
        // Sentinel: add custom
        rows.push(ProviderRow {
            id: "__add_custom__".into(),
            name: "+ Add custom OpenAI-compatible…".into(),
            is_builtin: false,
            needs_account: false,
            console_url: String::new(),
            auth_hint: "Set provider id + base URL + API key".into(),
            default_base: String::new(),
            default_model: String::new(),
        });
        self.rows = rows;
        if self.list_idx >= self.rows.len() {
            self.list_idx = self.rows.len().saturating_sub(1);
        }
    }

    pub fn selected(&self) -> Option<&ProviderRow> {
        self.rows.get(self.list_idx)
    }

    pub fn has_key(id: &str) -> bool {
        load_provider_api_key(id)
            .ok()
            .flatten()
            .map(|k| !k.is_empty())
            .unwrap_or(false)
    }

    pub fn is_default(&self, id: &str) -> bool {
        self.config.provider.id == id
    }

    pub fn actions_for_selected(&self) -> Vec<ProviderAction> {
        let Some(row) = self.selected() else {
            return vec![];
        };
        if row.id == "__add_custom__" {
            return vec![ProviderAction::AddCustom];
        }
        let mut a = vec![
            ProviderAction::SetDefault,
            ProviderAction::OpenConsole,
            ProviderAction::PasteKey,
            ProviderAction::EditModel,
            ProviderAction::EditBaseUrl,
        ];
        if Self::has_key(&row.id) {
            a.push(ProviderAction::ClearKey);
        }
        a
    }

    pub fn move_list(&mut self, delta: i32) {
        if self.rows.is_empty() {
            return;
        }
        let n = self.rows.len() as i32;
        let mut i = self.list_idx as i32 + delta;
        if i < 0 {
            i = n - 1;
        } else if i >= n {
            i = 0;
        }
        self.list_idx = i as usize;
        self.action_idx = 0;
        self.edit = None;
        if let Some(r) = self.selected() {
            let st = if Self::has_key(&r.id) {
                "key ✓"
            } else {
                "no key"
            };
            self.flash = Some(format!("{} · {st} · {}", r.name, r.auth_hint));
        }
    }

    pub fn move_action(&mut self, delta: i32) {
        let actions = self.actions_for_selected();
        if actions.is_empty() {
            return;
        }
        let n = actions.len() as i32;
        let mut i = self.action_idx as i32 + delta;
        if i < 0 {
            i = n - 1;
        } else if i >= n {
            i = 0;
        }
        self.action_idx = i as usize;
    }

    pub fn drill_in(&mut self) {
        if self.selected().map(|r| r.id.as_str()) == Some("__add_custom__") {
            self.start_add_custom();
            return;
        }
        self.focus = ProviderFocus::Actions;
        self.action_idx = 0;
        self.flash = Some("↑↓ actions · Enter run · ← back to list".into());
    }

    /// true = close pane
    pub fn drill_out(&mut self) -> bool {
        if self.edit.is_some() {
            self.edit = None;
            self.flash = Some("edit cancelled".into());
            return false;
        }
        if self.focus == ProviderFocus::Actions {
            self.focus = ProviderFocus::List;
            self.flash = Some("↑↓ providers · → actions · Esc close".into());
            false
        } else {
            true
        }
    }

    fn start_add_custom(&mut self) {
        self.edit = Some(ProviderEdit::CustomId {
            buffer: "custom".into(),
            cursor: 6,
        });
        self.flash = Some("Custom provider id (e.g. my-proxy) · Enter next · Esc cancel".into());
    }

    pub fn activate(&mut self) {
        if self.edit.is_some() {
            self.commit_edit();
            return;
        }
        if self.focus == ProviderFocus::List {
            self.drill_in();
            return;
        }
        let actions = self.actions_for_selected();
        let Some(action) = actions.get(self.action_idx).copied() else {
            return;
        };
        let Some(row) = self.selected().cloned() else {
            return;
        };
        match action {
            ProviderAction::SetDefault => {
                if row.id == "__add_custom__" {
                    return;
                }
                let model = self
                    .config
                    .provider
                    .model
                    .clone()
                    .or_else(|| Some(row.default_model.clone()));
                self.config.activate_provider(&row.id, model);
                self.dirty = true;
                self.flash = Some(format!(
                    "Active → `{}` / {} (other providers stay loaded · /model)",
                    row.id,
                    self.config.provider.model.as_deref().unwrap_or("—")
                ));
                self.pending = Some(ProviderPaneAction::ConfigChanged);
            }
            ProviderAction::OpenConsole => {
                self.pending = Some(ProviderPaneAction::OpenBrowser {
                    url: row.console_url.clone(),
                    label: row.name.clone(),
                });
                self.flash = Some(format!(
                    "Browser: {} — then use «Paste API key»",
                    row.console_url
                ));
            }
            ProviderAction::PasteKey => {
                // Ensure this provider is selected as default when pasting
                self.config.provider.id = row.id.clone();
                if self.config.provider.model.is_none() {
                    self.config.provider.model = Some(row.default_model.clone());
                }
                self.dirty = true;
                self.pending = Some(ProviderPaneAction::PasteApiKey {
                    provider_id: row.id.clone(),
                });
            }
            ProviderAction::EditModel => {
                let cur = self
                    .config
                    .provider
                    .model
                    .clone()
                    .filter(|_| self.is_default(&row.id))
                    .unwrap_or_else(|| row.default_model.clone());
                let cursor = cur.chars().count();
                // Switching model edit always applies to the selected provider once set default
                if !self.is_default(&row.id) {
                    self.config.provider.id = row.id.clone();
                    self.dirty = true;
                }
                self.edit = Some(ProviderEdit::Model {
                    buffer: cur,
                    cursor,
                });
                self.flash = Some("Edit model id · Enter save · Esc cancel".into());
            }
            ProviderAction::EditBaseUrl => {
                let cur = if self.is_default(&row.id) {
                    self.config
                        .provider
                        .base_url
                        .clone()
                        .unwrap_or_else(|| row.default_base.clone())
                } else {
                    row.default_base.clone()
                };
                if !self.is_default(&row.id) {
                    self.config.provider.id = row.id.clone();
                    self.dirty = true;
                }
                let cursor = cur.chars().count();
                self.edit = Some(ProviderEdit::BaseUrl {
                    buffer: cur,
                    cursor,
                });
                self.flash = Some("Edit base URL · empty = provider default · Enter save · Esc cancel".into());
            }
            ProviderAction::ClearKey => {
                let _ = oscar_identity::delete_provider_api_key(&row.id);
                self.flash = Some(format!("Cleared keychain key for `{}`", row.id));
            }
            ProviderAction::AddCustom => self.start_add_custom(),
        }
    }

    fn commit_edit(&mut self) {
        let Some(edit) = self.edit.take() else {
            return;
        };
        match edit {
            ProviderEdit::Model { buffer, .. } => {
                let v = buffer.trim().to_string();
                if v.is_empty() {
                    self.config.provider.model = None;
                } else {
                    self.config.provider.model = Some(v.clone());
                }
                self.dirty = true;
                self.flash = Some(format!("model → {}", v.if_empty("(default)")));
                self.pending = Some(ProviderPaneAction::ConfigChanged);
            }
            ProviderEdit::BaseUrl { buffer, .. } => {
                let v = buffer.trim().to_string();
                if v.is_empty() {
                    self.config.provider.base_url = None;
                    self.flash = Some("base_url → (provider default)".into());
                } else {
                    self.config.provider.base_url = Some(v.clone());
                    self.flash = Some(format!("base_url → {v}"));
                }
                self.dirty = true;
                self.pending = Some(ProviderPaneAction::ConfigChanged);
            }
            ProviderEdit::CustomId { buffer, .. } => {
                let id = buffer
                    .trim()
                    .to_ascii_lowercase()
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
                    .collect::<String>();
                if id.is_empty() || BUILTIN_PROVIDERS.iter().any(|m| m.id == id) {
                    self.flash = Some("invalid or reserved id — try again".into());
                    self.edit = Some(ProviderEdit::CustomId {
                        buffer: id,
                        cursor: 0,
                    });
                    return;
                }
                self.config.provider.id = id.clone();
                self.edit = Some(ProviderEdit::CustomUrl {
                    buffer: "https://".into(),
                    cursor: 8,
                });
                self.flash = Some(format!(
                    "Custom id `{id}` — enter base URL (OpenAI-compatible …/v1)"
                ));
                self.dirty = true;
            }
            ProviderEdit::CustomUrl { buffer, .. } => {
                let url = buffer.trim().to_string();
                if url.is_empty() || !url.starts_with("http") {
                    self.flash = Some("base URL required (https://…)".into());
                    self.edit = Some(ProviderEdit::CustomUrl {
                        buffer: url,
                        cursor: 0,
                    });
                    return;
                }
                self.config.provider.base_url = Some(url.clone());
                self.config.provider.model = self
                    .config
                    .provider
                    .model
                    .clone()
                    .or_else(|| Some("default".into()));
                self.dirty = true;
                self.rebuild_rows();
                if let Some(i) = self
                    .rows
                    .iter()
                    .position(|r| r.id == self.config.provider.id)
                {
                    self.list_idx = i;
                }
                self.focus = ProviderFocus::Actions;
                self.action_idx = 2; // paste key-ish
                self.flash = Some(format!(
                    "Custom `{id}` @ {url} — now paste API key",
                    id = self.config.provider.id
                ));
                self.pending = Some(ProviderPaneAction::PasteApiKey {
                    provider_id: self.config.provider.id.clone(),
                });
            }
        }
    }

    pub fn take_pending(&mut self) -> Option<ProviderPaneAction> {
        self.pending.take()
    }

    // ── edit buffer key helpers ───────────────────────────────────────────

    pub fn edit_insert(&mut self, c: char) {
        let Some(edit) = &mut self.edit else { return };
        let (buf, cur) = match edit {
            ProviderEdit::Model { buffer, cursor }
            | ProviderEdit::BaseUrl { buffer, cursor }
            | ProviderEdit::CustomId { buffer, cursor }
            | ProviderEdit::CustomUrl { buffer, cursor } => (buffer, cursor),
        };
        let i = byte_index(buf, *cur);
        buf.insert(i, c);
        *cur += 1;
    }

    pub fn edit_backspace(&mut self) {
        let Some(edit) = &mut self.edit else { return };
        let (buf, cur) = match edit {
            ProviderEdit::Model { buffer, cursor }
            | ProviderEdit::BaseUrl { buffer, cursor }
            | ProviderEdit::CustomId { buffer, cursor }
            | ProviderEdit::CustomUrl { buffer, cursor } => (buffer, cursor),
        };
        if *cur == 0 {
            return;
        }
        let start = byte_index(buf, *cur - 1);
        let end = byte_index(buf, *cur);
        buf.replace_range(start..end, "");
        *cur -= 1;
    }

    pub fn edit_home(&mut self) {
        if let Some(edit) = &mut self.edit {
            match edit {
                ProviderEdit::Model { cursor, .. }
                | ProviderEdit::BaseUrl { cursor, .. }
                | ProviderEdit::CustomId { cursor, .. }
                | ProviderEdit::CustomUrl { cursor, .. } => *cursor = 0,
            }
        }
    }

    pub fn edit_end(&mut self) {
        if let Some(edit) = &mut self.edit {
            match edit {
                ProviderEdit::Model { buffer, cursor }
                | ProviderEdit::BaseUrl { buffer, cursor }
                | ProviderEdit::CustomId { buffer, cursor }
                | ProviderEdit::CustomUrl { buffer, cursor } => *cursor = buffer.chars().count(),
            }
        }
    }

    pub fn edit_left(&mut self) {
        if let Some(edit) = &mut self.edit {
            match edit {
                ProviderEdit::Model { cursor, .. }
                | ProviderEdit::BaseUrl { cursor, .. }
                | ProviderEdit::CustomId { cursor, .. }
                | ProviderEdit::CustomUrl { cursor, .. } => {
                    if *cursor > 0 {
                        *cursor -= 1;
                    }
                }
            }
        }
    }

    pub fn edit_right(&mut self) {
        if let Some(edit) = &mut self.edit {
            match edit {
                ProviderEdit::Model { buffer, cursor }
                | ProviderEdit::BaseUrl { buffer, cursor }
                | ProviderEdit::CustomId { buffer, cursor }
                | ProviderEdit::CustomUrl { buffer, cursor } => {
                    if *cursor < buffer.chars().count() {
                        *cursor += 1;
                    }
                }
            }
        }
    }

    pub fn edit_clear(&mut self) {
        if let Some(edit) = &mut self.edit {
            match edit {
                ProviderEdit::Model { buffer, cursor }
                | ProviderEdit::BaseUrl { buffer, cursor }
                | ProviderEdit::CustomId { buffer, cursor }
                | ProviderEdit::CustomUrl { buffer, cursor } => {
                    buffer.clear();
                    *cursor = 0;
                }
            }
        }
    }

    pub fn edit_display(&self) -> Option<(String, usize, &'static str)> {
        match &self.edit {
            Some(ProviderEdit::Model { buffer, cursor }) => {
                Some((buffer.clone(), *cursor, "model"))
            }
            Some(ProviderEdit::BaseUrl { buffer, cursor }) => {
                Some((buffer.clone(), *cursor, "base_url"))
            }
            Some(ProviderEdit::CustomId { buffer, cursor }) => {
                Some((buffer.clone(), *cursor, "custom id"))
            }
            Some(ProviderEdit::CustomUrl { buffer, cursor }) => {
                Some((buffer.clone(), *cursor, "base_url"))
            }
            None => None,
        }
    }

    /// Snapshot of active ProviderSettings after edits.
    pub fn provider_settings(&self) -> &ProviderSettings {
        &self.config.provider
    }
}

fn byte_index(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(i, _)| i)
        .unwrap_or(s.len())
}

trait IfEmpty {
    fn if_empty(self, d: &str) -> String;
}
impl IfEmpty for String {
    fn if_empty(self, d: &str) -> String {
        if self.is_empty() {
            d.into()
        } else {
            self
        }
    }
}
