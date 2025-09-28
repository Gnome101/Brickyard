#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-http://127.0.0.1:8787}"

payload_design=$(cat <<JSON
{
  "prompt": "space rover",
  "agent_types": ["A", "B"]
}
JSON
)

echo "# POST /api/design"
response_design=$(curl -sS -X POST "$HOST/api/design" \
  -H 'content-type: application/json' \
  -d "$payload_design")

if command -v jq &>/dev/null; then
  echo "$response_design" | jq '.'
else
  echo "$response_design"
fi

echo "# POST /api/vote"
response_vote=$(curl -sS -X POST "$HOST/api/vote" \
  -H 'content-type: application/json' \
  -d '{"agent_type":"A","prompt":"space rover"}')

if command -v jq &>/dev/null; then
  echo "$response_vote" | jq '.'
else
  echo "$response_vote"
fi

echo "# GET /api/leaderboard"
response_leaderboard=$(curl -sS "$HOST/api/leaderboard")

if command -v jq &>/dev/null; then
  echo "$response_leaderboard" | jq '.'
else
  echo "$response_leaderboard"
fi
