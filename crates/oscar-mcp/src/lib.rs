//! MCP client (stdio JSON-RPC) and bridge into oscar's first-class ToolRegistry.
//!
//! Design: MCP tools are **not** dumped into the system prompt. They are discovered via
//! `tools_search` / `tools_execute` like native tools (`mcp.<server>.<tool>`).

mod bridge;
mod client;
mod manager;
mod oauth;

pub use bridge::{connect_and_register, register_mcp_tools, McpToolBridge};
pub use client::{McpClient, McpRemoteTool};
pub use manager::{McpManager, McpServerStatus};
pub use oauth::{
    apply_stored_token, clear_token, get_access_token, load_credentials, register_oauth_client,
    run_oauth_login, set_access_token, token_status,
};
