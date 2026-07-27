# MCP as first-class Code Mode tools

## Goal
Onboard MCP servers via TOML (like Grok Build) but **do not** dump MCP tool schemas into the system prompt. Instead, mount each remote tool as a first-class inventory entry discoverable only via `tools_search` / `tools_execute` (`mcp.<server>.<tool>`).

## Why
- Keeps Code Mode token budget fixed (~two agent tools).
- MCP inventories can be large; search is the right discovery surface.
- Aligns with oscar's multi-cloud registry model.

## Architecture
```
config.toml [mcp.servers.*]
        │
        ▼
 oscar-mcp::McpManager.connect_all()
        │  stdio JSON-RPC (Content-Length)
        ▼
 tools/list → McpToolBridge implements Tool
        │
        ▼
 ToolRegistry (same as aws.*, gcp.*, …)
        │
        ▼
 tools_search / tools_execute  (agent never sees full MCP list up front)
```

## Config (TOML)
```toml
[mcp]
enabled = true
max_output_bytes = 20000

[mcp.servers.filesystem]
enabled = true
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
install_hint = "Node + npx, or npm i -g @modelcontextprotocol/server-filesystem"
```

## Task board
- [x] M1 TOML schema `McpSettings` / `McpServerConfig` in oscar-core
- [x] M2 stdio JSON-RPC client (initialize, tools/list, tools/call)
- [x] M3 Bridge `McpToolBridge` → ToolRegistry with id `mcp.<server>.<tool>`
- [x] M4 Connect at agent build (`build_registry_with_mcp`)
- [x] M5 CLI: oscar mcp list|add|remove|enable|disable|doctor|tools|example
- [x] M6 HTTP/SSE transport (JSON-RPC POST + SSE data: parsing)
- [x] M6b OAuth: PKCE `oscar mcp auth`, `set-token`/`logout`, `mcp_credentials.json` auto Bearer inject + refresh
- [x] M6c Dynamic client registration (`oauth_registration_url` when client_id unset)
- [x] M7 Settings TUI category for MCP enable/disable per server (`/settings` → MCP servers)
- [x] M8 Project-scoped `.oscar/config.toml` mcp merge (G7 walk-up from cwd)
- [x] M9 MCP remount helpers (`oscar mcp reload`, `/mcp reload` in-session remount, enable/disable remounts live agent)
- [x] M10 Write capability inference / user override per MCP tool (`infer_mcp_capability`, `tool_capabilities`, `capability_default`; Write still mode-gated)
- [x] M11 Install helpers (`oscar mcp install <preset>` / `oscar mcp presets`) for common servers

## UX
- Onboard: `oscar mcp add …`, `oscar mcp install <preset>`, or edit TOML (`[mcp.servers.*]`)
- Presets: `oscar mcp presets` → filesystem | git | memory | fetch | time | sequential-thinking
- Validate: `oscar mcp doctor`
- Agent: `tools_search "mcp"` then `tools_execute` with `mcp.<server>.<tool>`
- Capability: keyword inference + `[mcp.servers.X] capability_default` / `tool_capabilities` map (Write needs readwrite mode)
- User TUI: `/settings` → **MCP servers**, slash `/mcp list|enable|disable`
- Project: optional `.oscar/config.toml` merges servers into user config

## Code Mode vs Grok Build

| Concern | Grok Build | oscar |
|---|---|---|
| Discovery | `search_tool` (MCP-only meta-tool) | `tools_search` (unified inventory: native + MCP) |
| Execute | `use_tool` with `server__tool` | `tools_execute` with `mcp.<server>.<tool>` (also accepts `server__tool`) |
| Context cost | MCP not dumped into system prompt | Same: fixed two agent tools |
| Transport | stdio + HTTP/SSE + OAuth | stdio + HTTP/SSE + OAuth PKCE (refresh + DCR) |
| Result size | truncate + spill under session `mcp/` | truncate + spill under `artifacts/mcp/` |
| Write safety | permission rules `MCPTool(server__*)` | mode gate + capability inference |

## Non-goals (v0)
- Dumping all MCP schemas into system prompt
- Auto-approving destructive MCP tools without mode gate
