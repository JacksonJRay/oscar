# Streaming, cancel, and reconnect

## How streaming works

Aligned with **Grok Build** (sampler L2 transform) and **OpenCode** (session processor + SSE bus):

1. **Chat input (TUI)** — Enter submits to the host via `user_tx`; host runs `agent.run_turn` while still listening for cancel.
2. **Provider SSE** — HTTP body → UTF-8 BOM strip → `eventsource-stream` → `data:` payloads (`SseDataStream`).
3. **Normalize** — Provider frames → `ProviderStreamEvent` (`ContentDelta`, `ThinkingDelta`, `ToolCall*`, `Usage`, `MessageStop`, `Error`).
4. **Finalize** — Tool call fragments always flush to `ToolCallDone` at finish_reason **or** stream end; `MessageStop` is always emitted (Grok Build pattern: force `ToolCalls` if tools present).
5. **Agent loop** — Maps stream events → `AgentEvent` for the TUI / headless NDJSON; runs tools then continues the model round.

```
TUI input ──user_tx──► host ──run_turn──► provider.chat_stream (SSE)
     │                        │                    │
     │ (queue if busy)        │◄── AgentEvent ◄────┘
     └── prompt_queue ────────┘    tools → next model round

oscar serve ──► POST /prompt → same agent loop
                GET  /event  → SSE of AgentEvent JSON
```

## Idle timeout

Provider streams abort with `ProviderStreamEvent::Error` if no SSE data arrives for
**90s** (`STREAM_IDLE_TIMEOUT`). Connect timeout is **20s**. Non-stream `chat` has a
**180s** overall request timeout.

## Prompt queue

While a turn is streaming, further Enter presses **queue** chat text. On
`AgentEvent::Done`, the next queued prompt is auto-submitted (slash commands wait
for idle, except `/quit`).

## Local SSE server (always-on with TUI)

When you run `oscar` (TUI), an SSE hub starts **by default** with a **watchdog**
that restarts the accept loop if the socket dies.

```toml
# ~/.config/oscar/config.toml
[sse]
enabled = true
bind = "127.0.0.1:4096"
watchdog = true
restart_backoff_ms = 500
restart_backoff_max_ms = 15000
```

Env: `OSCAR_SSE_BIND`, `OSCAR_SSE_DISABLE=1`, `OSCAR_SERVE_BIND`.

```bash
oscar                              # TUI + SSE hub
curl -N http://127.0.0.1:4096/event
curl -sS -X POST http://127.0.0.1:4096/prompt -d 'say hi'

oscar serve --bind 127.0.0.1:4096  # headless-only (same hub + watchdog)
```

Endpoints: `GET /health`, `GET /event` (SSE of `AgentEvent` JSON), `POST /prompt`, `POST /cancel`.

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
