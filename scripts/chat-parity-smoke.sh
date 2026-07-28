#!/usr/bin/env bash
# Grok Build chat parity smoke via agent-tui (Wave 1+).
# Usage: ./scripts/chat-parity-smoke.sh [path/to/oscar]
set -euo pipefail
export PATH="${HOME}/.local/bin:${HOME}/bin:${PATH}"
OSCAR_BIN="${1:-oscar}"
if [[ ! -x "$OSCAR_BIN" && -x "./target/debug/oscar" ]]; then
  OSCAR_BIN="./target/debug/oscar"
fi
if [[ ! -x "$OSCAR_BIN" && -x "./target/release/oscar" ]]; then
  OSCAR_BIN="./target/release/oscar"
fi
command -v agent-tui >/dev/null || {
  echo "agent-tui not on PATH" >&2
  exit 1
}
agent-tui daemon start >/dev/null 2>&1 || true
agent-tui sessions cleanup --yes >/dev/null 2>&1 || true

cleanup() {
  agent-tui kill -s "${SID:-}" --yes >/dev/null 2>&1 || agent-tui kill --yes >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== chat-parity-smoke: $OSCAR_BIN =="
SID=$(agent-tui run --cols 120 --rows 36 --format json -- "$OSCAR_BIN" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["session_id"])')
echo "session=$SID"

agent-tui wait -s "$SID" -t 20000 "oscar" --assert
agent-tui wait -s "$SID" -t 12000 --stable

# A: /help
agent-tui type -s "$SID" "/help"
agent-tui press -s "$SID" Enter
agent-tui wait -s "$SID" -t 10000 "/model" --assert
agent-tui wait -s "$SID" -t 5000 --stable

# B: Esc does not quit (still shows oscar after Esc)
agent-tui press -s "$SID" Escape
sleep 0.2
agent-tui wait -s "$SID" -t 5000 "oscar" --assert

# C: Tab focus scrollback + Space back to prompt
agent-tui press -s "$SID" Tab
sleep 0.15
agent-tui press -s "$SID" Space
sleep 0.15
agent-tui type -s "$SID" "/copy"
agent-tui press -s "$SID" Enter
sleep 0.3
# flash or notice — app stays alive
agent-tui wait -s "$SID" -t 5000 "oscar" --assert

# D: one Ctrl+C on empty does not quit (needs double-press)
agent-tui press -s "$SID" "Ctrl+C" || true
sleep 0.25
agent-tui wait -s "$SID" -t 5000 "oscar" --assert

agent-tui screenshot -s "$SID" >/tmp/oscar-chat-parity-shot.txt || true
echo "screenshot: /tmp/oscar-chat-parity-shot.txt"
echo "PASS chat-parity-smoke (wave1 keys + help + copy)"
