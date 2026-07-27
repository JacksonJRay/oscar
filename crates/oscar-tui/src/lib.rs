//! Ratatui chat UI: scrollback, thinking, context meter, secure input, settings + identities.

mod app;
mod identities;
mod input;
mod provider_pane;
mod settings;
mod ui;

pub use app::{
    run_tui, AgentActivity, App, AppConfig, SessionAction, View, MAX_SCROLL_BACK_LINES,
    MAX_TRANSCRIPT_LINES,
};
pub use identities::IdentitiesPane;
pub use input::{IdleHintRotator, InputMode, IDLE_HINT_INTERVAL, IDLE_INPUT_HINTS};
pub use settings::{SettingsPane, ToolCatalogEntry};
