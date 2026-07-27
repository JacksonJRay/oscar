//! Shared types, errors, and configuration for **oscar**.

pub mod access;
pub mod audit;
pub mod chat_history;
pub mod config;
pub mod discovery;
pub mod error;
pub mod events;
pub mod mcp_config;
pub mod messages;
pub mod redact;
pub mod skills;
pub mod types;

pub use access::{
    AccessBinding, AccessCheckResult, AccessDecision, AccessEntity, AccessInventory,
    AccessMutation, AccessObjectKind,
};
pub use audit::{append_tool_audit, audit_tool_execute, ToolAuditEvent};
pub use chat_history::{
    current_session_id, delete_session, list_sessions, load_current_or_latest, load_session,
    save_compaction_checkpoint, save_session, set_current_session_id, CompactionCheckpoint,
    SessionSummary, StoredChatSession, TranscriptLine,
};
pub use config::{
    InstallBinariesPolicy, McpServerConfig, McpSettings, OscarConfig, Paths, SkillsSettings,
    ToolsSettings,
};
pub use mcp_config::{expand_env_string, infer_mcp_capability, mcp_tool_id};
pub use skills::{
    discover_skills, find_skill, skills_catalog_prompt, user_skills_dir, Skill,
};
pub use discovery::{
    best_field_match, match_ip_or_cidr, match_text, DiscoveryHit, DiscoveryResult, MatchMode,
    PatternQuery, ResourceKind,
};
pub use error::{OscarError, OscarResult};
pub use events::{format_token_count, AgentEvent, CompactReason, ContextSnapshot};
pub use messages::{FinishReason, Message, MessageRole, ThinkingConfig, TokenUsage, ToolCall};
pub use redact::{looks_like_secret_leak, redact_json, redact_text};
pub use types::*;
