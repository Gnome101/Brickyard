#!/usr/bin/env bash
set -euo pipefail

# Integration test for the deployed Brickyard Worker.
# Verifies:
#  1) POST /api/design returns text/plain LDraw content (non-empty, contains part lines)
#  2) POST /api/vote increments the leaderboard count for the given agent

HOST="${HOST:-${1:-https://brickyard-worker.rileyseefeldt.workers.dev}}"
PROMPT="${PROMPT:-a small red car}"
MODEL="${MODEL:-claude-3-5-sonnet}"

echo "Using HOST=$HOST"
echo "PROMPT=$PROMPT"
echo "MODEL=$MODEL"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "\n[1/2] Testing POST /api/design returns LDraw..."
curl -sS -o "$tmpdir/ldr.txt" -D "$tmpdir/headers.txt" \
  -H 'content-type: application/json' \
  -X POST "$HOST/api/design" \
  -d "{\"prompt\":\"$PROMPT\",\"model\":\"$MODEL\",\"seed\":12345}"

ctype=$(awk -F': ' 'BEGIN{IGNORECASE=1} tolower($1)=="content-type"{print $2}' "$tmpdir/headers.txt" | tr -d '\r')
if [[ "$ctype" != text/plain* ]]; then
  echo "ERROR: expected content-type text/plain, got: $ctype" >&2
  exit 1
fi

if ! grep -Eq '^1\s+[0-9]+\s+-?\d+(\.\d+)?\s+-?\d+(\.\d+)?\s+-?\d+(\.\d+)?\s+-?1|0|1\s+.*\.dat$' "$tmpdir/ldr.txt"; then
  # fallback: just check that at least one type-1 line with .dat appears
  if ! grep -Eq '^1\s+.*\.dat$' "$tmpdir/ldr.txt"; then
    echo "ERROR: LDraw body does not appear to contain part lines (.dat)" >&2
    echo "First 20 lines:" >&2
    sed -n '1,20p' "$tmpdir/ldr.txt" >&2
    exit 1
  fi
fi

echo "OK: /api/design returned plausible LDraw (text/plain)."

echo "\n[2/2] Testing /api/vote increments leaderboard..."

extract_count() {
  local json="$1"
  local key="$2"
  if command -v jq >/dev/null 2>&1; then
    echo "$json" | jq -r --arg k "$key" '.leaderboard[$k] // 0'
  else
    python3 - "$key" <<'PY'
import json, sys
data = json.load(sys.stdin)
key = sys.argv[1]
print(int((data.get('leaderboard') or {}).get(key, 0)))
PY
  fi
}

lb_before_json=$(curl -sS "$HOST/api/leaderboard")
before=$(extract_count "$lb_before_json" "$MODEL")

vote_json=$(curl -sS -X POST "$HOST/api/vote" \
  -H 'content-type: application/json' \
  -d "{\"agent_type\":\"$MODEL\",\"prompt\":\"$PROMPT\"}")

lb_after_json=$(curl -sS "$HOST/api/leaderboard")
after=$(extract_count "$lb_after_json" "$MODEL")

if [[ "$after" -lt $((before + 1)) ]]; then
  echo "ERROR: leaderboard did not increment as expected (before=$before, after=$after)" >&2
  echo "Vote response: $vote_json" >&2
  echo "After leaderboard: $lb_after_json" >&2
  exit 1
fi

echo "OK: /api/vote incremented leaderboard ($before -> $after)."

echo "\nAll integration checks passed."

