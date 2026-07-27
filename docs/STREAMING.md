# Streaming, cancel, and reconnect

## How streaming works

1. The agent calls the LLM provider via `chat_stream` (SSE where the API supports it).
2. Provider-specific frames are normalized to `ProviderStreamEvent` (`ContentDelta`, `ThinkingDelta`, `ToolCall*`, `Usage`, `MessageStop`, `Error`).
3. The agent loop maps those into `AgentEvent` for the TUI / headless NDJSON consumer.

## Cancel (Esc / Ctrl+C)

| Surface | Behavior |
|---|---|
| TUI Esc during a turn | Host cancels the `CancellationToken` for the turn |
| `oscar ask` Ctrl+C | Process interrupt; in-flight stream drops |

Agent loop checks:

- Before each model round
- Before each tool in `handle_tool_calls`
- Plugin tools check `ctx.cancel` at start

When cancelled mid-stream, the host should:

1. Stop reading the HTTP body (drop the stream future).
2. Emit `Done` with last-known usage if any.
3. Leave session messages in a consistent state (partial assistant text may remain; next user turn continues).

**Do not** retry a cancelled mid-stream request without an explicit user re-prompt (avoids duplicate side effects).

## Provider reconnect policy

| Stage | Retry? |
|---|---|
| Connect / TLS / DNS failure before any content | Soft retry 1–2× with backoff (host optional) |
| After first `ContentDelta` / tool delta | **No automatic retry** (partial content already shown) |
| HTTP 429 / 5xx before stream body | Optional retry with `Retry-After` if present |
| Stream idle timeout | Cancel token; surface error; user re-runs |

Oscar v0 does not auto-resume SSE after partial content. Providers that support request IDs / resume are future work.

## Headless NDJSON

```bash
oscar ask --stream "why is dns broken?"
# stdout: AgentEvent lines (content, tools, context, done)
```

Treat the stream as **best-effort sequential events**. On process kill, assume incomplete.

## Tool-side cancel

Long CSP analyzers (Reachability, Connectivity Tests) should honor `ToolContext.cancel` when polling. If a tool ignores cancel, the agent still stops scheduling further tools after cancel is set.

## Related

- Context auto-compact still runs on turn boundaries even after a cancelled previous turn.
- MCP tool calls use per-tool timeouts (`tool_timeout_sec` / `tool_timeouts`).
