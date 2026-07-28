# Oscar chat TUI — Grok Build parity plan

Living plan to make oscar’s agent chat pane behave like **Grok Build**: scrollback entries, prompt, queue, streaming response, thinking, tool calls, copy, cancel, and status chrome.

**How to use:** work top‑down by wave. Mark items `[x]` when agent‑tui or unit tests pass. Do not claim “done” without a test note.

**Related:** [TESTING-TUI.md](TESTING-TUI.md), [STREAMING.md](STREAMING.md), [BEHAVIOR-CHANGE-PLAN.md](BEHAVIOR-CHANGE-PLAN.md), Grok user guide `03-keyboard-shortcuts.md` / `04-slash-commands.md`.

---

## Target product shape (Grok Build)

```
┌ status: oscar │ mode │ context │ profile │ activity (thinking/tool/answering/ready) ┐
├ chat / scrollback ─────────────────────────────────────────────────────────────────┤
│  ❯ user turn                                                                       │
│  ◆ Thought · done (N)                                                              │
│  ┃  thinking body (optional / foldable)                                            │
│  ┃  ◆ tool_id                                                                      │
│  ┃    args: …                                                                      │
│  ❙  ✓ tool_id · summary                                                            │
│  assistant answer (markdown tables, not raw pipes)                                 │
│  (select whole entries; y copies block content)                                    │
├ input ─────────────────────────────────────────────────────────────────────────────┤
│  > prompt · queue badge · model                                                    │
│  hints: Tab focus · Esc cancel · y copy · /commands                                │
└────────────────────────────────────────────────────────────────────────────────────┘
```

### Behavioral contracts (must match Grok spirit)

| Area | Grok Build | Oscar must |
|------|------------|------------|
| **Submit** | Enter sends; mid-turn Enter **queues** | Queue while `awaiting_reply`/`streaming`; show `queued #N` |
| **Queue drain** | Auto after turn ends | Dequeue on `Done` (preserve draft cancel semantics) |
| **Response stream** | Tokens append to one assistant block | One continuous assistant block per turn; pin to bottom while following |
| **Thinking** | Header always; body optional; foldable | Header + optional body; toggle `/thinking` or Ctrl+T; collapse body by default option |
| **Tools** | Rail: start → args → ✓/✗ end | `ToolStart` / `ToolEnd` cards; activity = tool id |
| **Scrollback select** | Click/↑↓ = **entry**, not wrap-row | Block selection (user / assistant / tool / thinking) |
| **Copy** | `y` = block; mouse **drag** = character range (text_selection); `/copy` = last reply; multi-route clipboard | Drag selects chars (not whole turns); click = entry for `y`; release after drag auto-copies; long-lived clipboard owner |
| **Focus** | Tab / Space → prompt; Tab → scrollback | Same |
| **Cancel** | Esc cancels turn (draft kept); Ctrl+C clear-then-cancel | Esc cancel when streaming; **do not quit on first Esc**; Ctrl+C: clear draft → cancel → quit double |
| **Idle Esc** | Esc Esc clear prompt / rewind | Esc Esc clear non-empty prompt; Esc alone when empty does **not** quit |
| **Scroll while reading** | Stick only when following tail | Never force pin on `Done` if user scrolled up |
| **Status** | Live activity | Spinner for thinking/tool/answering; ready when idle |
| **Markdown** | Rendered tables/headers | TUI formatter (no raw `\|---\|`) |

Out of scope for this plan (track elsewhere): full vim mode, rewind picker, background-task status line, ACP, worktrees.

---

## Current state (audit 2026-07-28)

### Already close
- [x] Prompt queue (`prompt_queue` + `queued #N` + drain on Done)
- [x] Thinking header + body (`ThinkingDelta` / `ThinkingDone`)
- [x] Tool rail (`◆` / args / `✓`)
- [x] Activity spinner in status
- [x] Block selection + Grok-like copy (recent)
- [x] Visual mouse hit-test for wrap rows
- [x] Markdown table display pass
- [x] Secure bar bulk AWS paste + secrets dir
- [x] agent-tui skill + smoke script

### Gaps / bugs (priority)

| ID | Gap | Severity | Wave |
|----|-----|----------|------|
| C1 | **Esc quits** when idle (should clear/select/no-op, not exit) | High | 1 |
| C2 | **Ctrl+C quits** immediately (Grok: clear draft → cancel → double quit) | High | 1 |
| C3 | **Space** does not always return to prompt from scrollback | Med | 1 |
| C4 | Queue has no **status chrome** (count on input/status) | Med | 1 |
| C5 | Thinking body always expands when `show_thinking`; no fold | Med | 2 |
| C6 | Multi-line assistant stream can create multiple logical lines → choppy select | Med | 2 |
| C7 | `✓ done — ready` noise every turn | Low | 1 |
| C8 | Enter mid-queue cannot “send now” (Grok Ctrl+Enter) — optional | Low | 3 |
| C9 | Scroll page while prompt-focused still coarse | Low | 2 |
| C10 | Copy flash / status can fight with input hints | Low | 2 |
| C11 | No automated suite covering queue+cancel+copy together | High | 1 |
| C12 | Stick-to-bottom vs selection edge cases under stream | Med | 2 |

---

## Waves

### Wave 1 — Input / cancel / queue chrome (must not feel broken)
**Goal:** keys and queue match Grok “don’t accidentally quit; always recoverable.”

- [x] **C1** Esc ladder: slash menu → secure cancel → clear selection → cancel stream → clear prompt (double Esc) → **never** single-Esc quit
- [x] **C2** Ctrl+C: non-empty clear → empty+streaming cancel → empty idle double-press quit (1s)
- [x] **C3** Space (scrollback) focuses prompt without inserting space
- [x] **C4** Status shows `queue:N` when non-empty
- [x] **C7** Soften Done notice (toast flash, not permanent chat line)
- [x] **C11** `scripts/chat-parity-smoke.sh` + unit tests for Esc/Ctrl+C state machine

### Wave 2 — Transcript quality (read / select / stream)
**Goal:** one clean entry per turn segment; smooth scroll/copy.

- [x] **C5** Collapse thinking body rails after `ThinkingDone` (keep header chip)
- [x] **C6** Assistant stream already appends to one block; tool/thinking separate (verified)
- [x] **C9** Page scroll ≈ ½ viewport height
- [x] **C10** Copy/status toast on input title; auto-clear ~2.2s (`set_flash` / `tick_flash`)
- [x] **C12** Stick-to-bottom only when following tail (Done does not force pin if scrolled up)

### Wave 3 — Power features (optional Grok parity)
- [ ] **C8** Ctrl+Enter / send-now: cancel current + send draft (or dequeue top)
- [ ] Queue list slash `/queue` show/clear
- [ ] Half-page Ctrl+U/D
- [ ] Entry collapse for huge tool dumps

### Wave 4 — Hardening
- [ ] agent-tui matrix: boot, help, stream (if creds), queue, cancel, copy, scroll, provider gate
- [ ] No regression on secure bar / auth resume
- [ ] CHANGELOG entry “Chat TUI Grok parity”

---

## Acceptance (full feature / no bug chat)

A release of this plan is **accepted** when:

1. **Boot** — status + empty chat + prompt; provider gate if no key.
2. **Send** — user line appears; activity shows thinking/answering; tokens stream into one assistant block.
3. **Thinking** — header visible; body respects show_thinking / fold.
4. **Tools** — start/end rail without blank silent gaps; short narration after tools (agent harness).
5. **Queue** — second Enter while busy → `queued #N` + badge; auto-send after Done.
6. **Cancel** — Esc stops stream; prompt usable; draft preserved on Esc cancel.
7. **Quit** — requires intentional double Ctrl+C or `/quit`, not single Esc.
8. **Copy** — select entry, `y` → plain text in clipboard + last-copy.txt; click does not dump full chat.
9. **Scroll** — reading mid-history is not yanked to bottom on Done.
10. **agent-tui** smoke script exits 0.

---

## Implementation notes

### Esc / Ctrl+C state machine (Wave 1)

```
on Esc:
  if slash_menu → close
  elif secure → cancel secure
  elif selection → clear selection
  elif streaming|awaiting → cancel turn (keep draft)
  elif prompt non-empty → arm clear (800ms); 2nd Esc → clear
  elif prompt empty → no-op (or open sessions later)
  # never quit

on Ctrl+C:
  if secure → cancel secure
  elif prompt non-empty → clear prompt
  elif streaming|awaiting → cancel turn
  elif idle empty → arm quit (1000ms); 2nd → quit
```

### Files to touch
- `crates/oscar-tui/src/app.rs` — keys, queue badge, Done noise, stick
- `crates/oscar-tui/src/ui.rs` — status queue, toast
- `crates/oscar-tui/src/input.rs` — hints
- `scripts/chat-parity-smoke.sh` — automated checks
- `docs/TESTING-TUI.md` — link this plan
- `CHANGELOG.md`

### Test commands
```bash
cargo test -p oscar-tui --lib
cargo build -p oscar-cli
./scripts/chat-parity-smoke.sh ./target/debug/oscar
# optional live model:
# ./scripts/agent-tui-smoke.sh ./target/debug/oscar
```

---

## Status log

| Date | Note |
|------|------|
| 2026-07-28 | Plan created from Grok docs + oscar audit. Prior copy/scroll/markdown/secrets work already landed. Wave 1 next. |
| 2026-07-28 | **Wave 1 landed:** Esc/Ctrl+C Grok ladder, queue badge, Space→prompt, Done toast, hold clipboard, block copy, unit tests + `scripts/chat-parity-smoke.sh`. |
| 2026-07-28 | **Wave 2 partial:** thinking body collapse after done; half-viewport page scroll; toast auto-clear. Wave 3 (send-now / queue pane) still open. |
| 2026-07-28 | **Clipboard Grok 1:1:** long-lived arboard owner thread (fixes “dropped very quickly after writing”); CLIPBOARD+PRIMARY on Linux; `wl-copy`/`xclip`/`xsel`/`tmux` fallbacks; OSC 52 only if live routes fail; always backup file + toast. |
| 2026-07-28 | **Continuous visual-row scroll:** `chat_scroll` is visual rows from bottom (not message index); wheel/Ctrl+↑↓ line steps; Page = viewport; half-page Ctrl+U/D. agent-tui scroll smoke + unit tests. |
| 2026-07-28 | **Text selection (from xai-org/grok-build pager):** `TextSelection` + `VisualHit` maps; drag selects char ranges; click without drag = entry block; copy prefers text range. |
