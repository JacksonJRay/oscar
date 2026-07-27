//! Agent runtime: system identity, tool loop, streaming, context management.

mod context;
mod loop_;
mod prompt;
mod session;

pub use context::{CompactConfig, CompactRequest, ContextManager};
pub use loop_::{Agent, AgentOptions, PendingInstall, PendingToolRetry};
pub use prompt::system_prompt;
pub use session::Session;
