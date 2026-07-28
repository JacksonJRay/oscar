#!/usr/bin/env bash
# Smoke-test oscar TUI via agent-tui (for humans or the Grok harness).
# Usage: scripts/agent-tui-smoke.sh [path-to-oscar]
set -euo pipefail

export PATH="${HOME}/.local/bin:${HOME}/bin:${PATH}"
OSCAR_BIN="${1:-$(command -v oscar)}"
COLS="${OSCAR_TUI_COLS:-140}"
ROWS="${OSCAR_TUI_ROWS:-45}"

if ! command -v agent-tui >/dev/null 2>&1; then
  echo "agent-tui missing — install: curl -fsSL https://raw.githubusercontent.com/pproenca/agent-tui/master/install.sh | bash" >&2
  exit 1
fi
if [[ ! -x "$OSCAR_BIN" ]]; then
  echo "oscar binary not found: $OSCAR_BIN" >&2
  exit 1
fi

agent-tui daemon start >/dev/null 2>&1 || true
agent-tui kill --yes >/dev/null 2>&1 || true

echo "==> run $OSCAR_BIN (${COLS}x${ROWS})"
SID=$(agent-tui run --cols "$COLS" --rows "$ROWS" --format json -- "$OSCAR_BIN" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["session_id"])')
echo "session=$SID"

cleanup() { agent-tui kill -s "$SID" --yes >/dev/null 2>&1 || agent-tui kill --yes >/dev/null 2>&1 || true; }
trap cleanup EXIT

agent-tui wait -s "$SID" -t 20000 "oscar" --assert
agent-tui wait -s "$SID" -t 10000 --stable
echo "==> boot OK"
agent-tui screenshot -s "$SID" | head -20

echo "==> /help"
agent-tui type -s "$SID" "/help"
agent-tui press -s "$SID" Enter
agent-tui wait -s "$SID" -t 10000 "/model" --assert
echo "==> /help OK"

echo "==> chat (short)"
agent-tui type -s "$SID" "Reply with exactly one word: pong"
agent-tui press -s "$SID" Enter
if agent-tui wait -s "$SID" -t 90000 "pong" --assert; then
  echo "==> chat OK (saw pong)"
else
  echo "==> chat WARN (no pong within timeout — screenshot follows)" >&2
  agent-tui screenshot -s "$SID" | tail -40
  exit 2
fi

agent-tui wait -s "$SID" -t 20000 --stable
agent-tui screenshot -s "$SID" | tail -25
echo "==> smoke passed"
