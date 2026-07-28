//! Grok Build–style session picker for `/resume`.
//!
//! Lists saved chats under `~/.config/oscar/sessions/`. Filter by typing;
//! Enter resumes the selected session via the host.

use oscar_core::{list_sessions, Paths, SessionSummary};

#[derive(Debug, Clone)]
pub enum SessionsPaneAction {
    /// Resume this session id (full uuid).
    Resume { id: String },
    Close,
}

pub struct SessionsPane {
    /// Full list from disk (newest first).
    pub all: Vec<SessionSummary>,
    /// Indices into `all` after filter.
    pub filtered: Vec<usize>,
    pub list_idx: usize,
    /// Live filter buffer (title / id / preview).
    pub filter: String,
    pub flash: Option<String>,
    pub pending: Option<SessionsPaneAction>,
    /// Current in-memory session (marked with *).
    pub current_id: String,
}

impl SessionsPane {
    pub fn open(current_id: impl Into<String>) -> Self {
        let current_id = current_id.into();
        let all = Paths::discover()
            .ok()
            .and_then(|p| list_sessions(&p).ok())
            .unwrap_or_default();
        let mut pane = Self {
            all,
            filtered: vec![],
            list_idx: 0,
            filter: String::new(),
            flash: Some(
                "↑↓ select · Enter resume · type to filter · Esc close · /new starts fresh"
                    .into(),
            ),
            pending: None,
            current_id,
        };
        pane.refilter();
        pane
    }

    pub fn refilter(&mut self) {
        let q = self.filter.to_ascii_lowercase();
        self.filtered = self
            .all
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                if q.is_empty() {
                    return true;
                }
                s.title.to_ascii_lowercase().contains(&q)
                    || s.id.to_ascii_lowercase().contains(&q)
                    || s.preview.to_ascii_lowercase().contains(&q)
                    || s.model.to_ascii_lowercase().contains(&q)
                    || s.provider.to_ascii_lowercase().contains(&q)
            })
            .map(|(i, _)| i)
            .collect();
        if self.list_idx >= self.filtered.len() {
            self.list_idx = self.filtered.len().saturating_sub(1);
        }
    }

    pub fn selected(&self) -> Option<&SessionSummary> {
        let i = *self.filtered.get(self.list_idx)?;
        self.all.get(i)
    }

    pub fn move_list(&mut self, delta: i32) {
        if self.filtered.is_empty() {
            return;
        }
        let n = self.filtered.len() as i32;
        let cur = self.list_idx as i32;
        self.list_idx = ((cur + delta).rem_euclid(n)) as usize;
    }

    pub fn activate(&mut self) {
        if let Some(s) = self.selected() {
            self.pending = Some(SessionsPaneAction::Resume {
                id: s.id.clone(),
            });
        } else {
            self.flash = Some("no sessions to resume — start chatting, then /resume later".into());
        }
    }

    pub fn take_pending(&mut self) -> Option<SessionsPaneAction> {
        self.pending.take()
    }

    pub fn push_filter_char(&mut self, c: char) {
        if !c.is_control() {
            self.filter.push(c);
            self.refilter();
        }
    }

    pub fn filter_backspace(&mut self) {
        self.filter.pop();
        self.refilter();
    }

    pub fn clear_filter(&mut self) {
        self.filter.clear();
        self.refilter();
    }
}
