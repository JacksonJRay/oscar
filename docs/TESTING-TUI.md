# Testing oscar TUI with agent-tui

**agent-tui is a harness tool** ([pproenca/agent-tui](https://github.com/pproenca/agent-tui)). It is **not** shipped inside oscar. Coding agents (Grok Build, etc.) use it to drive oscar’s Ratatui UI in a PTY.

## Install (once)

```bash
curl -fsSL https://raw.githubusercontent.com/pproenca/agent-tui/master/install.sh | bash
# ensure ~/.local/bin is on PATH
agent-tui --version
agent-tui daemon start
```

This machine also has a **native** binary at `~/.local/bin/agent-tui-bin` (and wrapper
`~/.local/bin/agent-tui`) so Grok Build shells work **without nvm/node on PATH**.

## Grok skills (this repo)

| Skill | Path | Purpose |
|-------|------|---------|
| `agent-tui` | `.grok/skills/agent-tui/` | Upstream skill: CLI, waits, recovery, command atlas |
| `test-oscar-tui` | `.grok/skills/test-oscar-tui/` | Oscar-specific UI tests, map, pass/fail |

Also installed for the user at `~/.grok/skills/agent-tui` and `~/.grok/skills/tui-explorer`.

In Grok: `/agent-tui`, `/test-oscar-tui`, or ask “test oscar TUI with agent-tui”.

## Quick smoke

```bash
# Use installed oscar, or pass a binary path
./scripts/agent-tui-smoke.sh
./scripts/agent-tui-smoke.sh ./target/release/oscar

# Grok Build chat parity (Esc/Ctrl+C/queue/copy keys — no live model required)
./scripts/chat-parity-smoke.sh ./target/debug/oscar
```

Chat UX roadmap: [CHAT-UPDATE.plan.md](CHAT-UPDATE.plan.md).

Manual loop:

```bash
agent-tui run --cols 140 --rows 45 --format json -- oscar
agent-tui screenshot
agent-tui type "/help" && agent-tui press Enter
agent-tui wait "/model" --assert
agent-tui type "Reply with exactly one word: pong" && agent-tui press Enter
agent-tui wait "pong" --assert -t 90000
agent-tui kill --yes
```

## What to cover with agent-tui (not flags alone)

| Feature | Why TUI? |
|---------|----------|
| Chat streaming | Tokens appear in chat pane |
| Prompt queue | Type while busy → `queued #N` |
| Esc cancel | Mid-turn abort |
| Slash menu | `/` popup + `/help` |
| Provider setup | Secure paste UX |
| Scrollback / copy | Pane focus, selection |

`oscar ask` / `oscar serve` remain useful unit-level checks; they do **not** replace TUI automation.
