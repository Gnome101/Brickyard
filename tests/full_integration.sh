#!/usr/bin/env bash
set -euo pipefail

# Comprehensive integration tests for the deployed Brickyard Worker.
# Validates routing, CORS preflight, content-types, success/error shapes,
# and DB-backed vote/leaderboard behavior.

HOST="${HOST:-${1:-https://brickyard-worker.rileyseefeldt.workers.dev}}"
PROMPT="${PROMPT:-a small red car}"
MODEL_OK="${MODEL_OK:-claude-3-5-sonnet}"
MODEL_BAD="${MODEL_BAD:-A}"
CLIENT_HEADER="${CLIENT_HEADER:-X-Client-Key}"
if [[ -z "${CLIENT_KEY:-}" ]]; then
  echo "ERROR: CLIENT_KEY is not set. Export your Worker client API key, e.g.:" >&2
  echo "  export CLIENT_KEY=\"<your-client-key>\"" >&2
  exit 2
fi

echo "Using HOST=$HOST"
echo "PROMPT=$PROMPT"
echo "MODEL_OK=$MODEL_OK"
echo "MODEL_BAD=$MODEL_BAD"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

req() {
  local method="$1" path="$2" data="${3-}"
  local url="$HOST$path"
  local body="$TMPDIR/body"
  local headers="$TMPDIR/headers"
  : >"$body"; : >"$headers"
  if [[ -n "$data" ]]; then
    STATUS=$(curl -sS -o "$body" -D "$headers" -w "%{http_code}" \
      -H 'content-type: application/json' \
      -H "$CLIENT_HEADER: ${CLIENT_KEY}" \
      -X "$method" "$url" -d "$data")
  else
    STATUS=$(curl -sS -o "$body" -D "$headers" -w "%{http_code}" \
      -H 'content-type: application/json' \
      -H "$CLIENT_HEADER: ${CLIENT_KEY}" \
      -X "$method" "$url")
  fi
  BODY_FILE="$body"; HEADERS_FILE="$headers"
}

header_ci() {
  local name="$1"
  awk -v n="$name" -F': ' 'BEGIN{IGNORECASE=1} tolower($1)==tolower(n){print $2}' "$HEADERS_FILE" | tr -d '\r'
}

assert() { # usage: assert "condition" "message"
  if ! eval "$1"; then
    echo "ASSERTION FAILED: $2" >&2
    echo "--- status: $STATUS" >&2
    echo "--- headers:" >&2
    cat "$HEADERS_FILE" >&2 || true
    echo "--- body (first 200 bytes):" >&2
    head -c 200 "$BODY_FILE" >&2 || true
    exit 1
  fi
}

json_get() {
  local expr="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r "$expr" <"$BODY_FILE"
  else
    python3 - "$expr" <"$BODY_FILE" <<'PY'
import json, sys
expr = sys.argv[1]
data = json.load(sys.stdin)
def get(d, path):
  cur = d
  for p in path.strip('.').split('.'):
    cur = cur.get(p) if isinstance(cur, dict) else None
  return cur
val = get(data, expr)
print(val if val is not None else '')
PY
  fi
}

echo "\n[1/10] GET /healthz"
req GET /healthz
ctype=$(header_ci content-type)
assert "[[ \"$STATUS\" == 200 ]]" "healthz status 200"
assert "[[ \"$ctype\" == application/json* ]]" "healthz is application/json"
assert "[[ \"$(json_get .ok)\" == true ]]" "healthz ok true"
assert "[[ -n \"$(json_get .request_id)\" ]]" "healthz request_id present"

echo "\n[2/10] OPTIONS /api/design (CORS preflight)"
req OPTIONS /api/design
allow_methods=$(header_ci access-control-allow-methods)
allow_headers=$(header_ci access-control-allow-headers)
assert "[[ \"$STATUS\" == 204 ]]" "preflight status 204"
assert "[[ \"$allow_methods\" == *GET* && \"$allow_methods\" == *POST* && \"$allow_methods\" == *OPTIONS* ]]" "preflight methods include GET,POST,OPTIONS"
assert "[[ \"$allow_headers\" == *content-type* ]]" "preflight allow headers include content-type"

echo "\n[3/10] GET /api/design should be 404"
req GET /api/design
ctype=$(header_ci content-type)
assert "[[ \"$STATUS\" == 404 ]]" "GET /api/design returns 404"
assert "[[ \"$ctype\" == application/json* ]]" "404 has JSON content-type"
assert "[[ \"$(json_get .error.code)\" == NOT_FOUND ]]" "404 error code NOT_FOUND"

echo "\n[4/10] POST /api/design returns LDraw (model key)"
req POST /api/design "{\"prompt\":\"$PROMPT\",\"model\":\"$MODEL_OK\",\"seed\":12345}"
ctype=$(header_ci content-type)
rid=$(header_ci x-request-id)
assert "[[ \"$STATUS\" == 200 ]]" "design status 200"
assert "[[ \"$ctype\" == text/plain* ]]" "design is text/plain"
assert "grep -Eq '^1\\s+.*\\.dat$' \"$BODY_FILE\"" "design contains LDraw type-1 lines"
assert "[[ -n \"$rid\" ]]" "x-request-id header present"

echo "\n[5/10] POST /api/design accepts agent_type (compat)"
req POST /api/design "{\"prompt\":\"$PROMPT\",\"agent_type\":\"$MODEL_OK\"}"
ctype=$(header_ci content-type)
assert "[[ \"$STATUS\" == 200 ]]" "design (agent_type) status 200"
assert "[[ \"$ctype\" == text/plain* ]]" "design (agent_type) is text/plain"
assert "grep -Eq '^1\\s+.*\\.dat$' \"$BODY_FILE\"" "design (agent_type) contains LDraw lines"

echo "\n[6/10] POST /api/design rejects missing prompt"
req POST /api/design "{}"
ctype=$(header_ci content-type)
assert "[[ \"$STATUS\" == 400 ]]" "design missing prompt -> 400"
assert "[[ \"$ctype\" == application/json* ]]" "error content-type JSON"
assert "[[ \"$(json_get .error.code)\" == VALIDATION_FAILED ]]" "error code VALIDATION_FAILED"

echo "\n[7/10] POST /api/design with bad model should surface upstream error"
req POST /api/design "{\"prompt\":\"$PROMPT\",\"model\":\"$MODEL_BAD\"}"
assert "[[ \"$STATUS\" == 502 || \"$STATUS\" == 500 ]]" "bad model returns 5xx"
assert "[[ \"$(json_get .error.code)\" == GENERATION_FAILED || \"$(json_get .error.code)\" == GENERATION_TIMEOUT ]]" "error code generation-related"

echo "\n[8/10] GET /api/leaderboard returns JSON with updated_at"
req GET /api/leaderboard
ctype=$(header_ci content-type)
assert "[[ \"$STATUS\" == 200 ]]" "leaderboard status 200"
assert "[[ \"$ctype\" == application/json* ]]" "leaderboard is JSON"
assert "[[ -n \"$(json_get .updated_at)\" ]]" "leaderboard has updated_at"

echo "\n[9/10] POST /api/vote validation (missing prompt)"
req POST /api/vote "{\"agent_type\":\"$MODEL_OK\"}"
assert "[[ \"$STATUS\" == 400 ]]" "vote missing prompt -> 400"
assert "[[ \"$(json_get .error.code)\" == VALIDATION_FAILED ]]" "vote validation error code"

echo "\n[10/10] POST /api/vote increments leaderboard"
# read before
req GET /api/leaderboard
before=$(json_get .leaderboard[\"$MODEL_OK\"]) || before=0
[[ -z "$before" ]] && before=0
req POST /api/vote "{\"agent_type\":\"$MODEL_OK\",\"prompt\":\"$PROMPT\"}"
assert "[[ \"$STATUS\" == 200 ]]" "vote status 200"
req GET /api/leaderboard
after=$(json_get .leaderboard[\"$MODEL_OK\"]) || after=0
assert "[[ ${after:-0} -ge $(( ${before:-0} + 1 )) ]]" "leaderboard incremented (before=$before, after=$after)"

echo "\nAll tests passed."
