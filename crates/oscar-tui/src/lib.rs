//! Ratatui chat UI: scrollback, thinking, context meter, secure input, settings + identities.
//!
//! Grok Build–style controllable panes: Tab focuses chat scrollback vs prompt;
//! select lines, highlight, copy (`y` / Ctrl+Y) and paste (Ctrl+V / bracketed paste).

mod app;
mod clipboard;
mod identities;
mod input;
mod provider_pane;
mod settings;
mod ui;

pub use app::{
    run_tui, AgentActivity, App, AppConfig, PaneFocus, SessionAction, View, MAX_SCROLL_BACK_LINES,
    MAX_TRANSCRIPT_LINES,
};
pub use clipboard::{copy_text, paste_text, CopyOutcome};
pub use identities::IdentitiesPane;
pub use input::{IdleHintRotator, InputMode, IDLE_HINT_INTERVAL, IDLE_INPUT_HINTS};
pub use settings::{SettingsPane, ToolCatalogEntry};
