#!/usr/bin/env bash
# dashboard.sh — open the live attack console at http://localhost:8900 (viewer).
#
# This does NOT attack anything. It shows the baseline, the latest run, the
# history of past runs, and updates live when you run ./attack.sh (or click
# "Launch attacks"). Results persist on disk, so refreshing or restarting keeps
# everything. Leave this running in its own terminal.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.sh"
export JUICE_URL="${JUICE_URL:-http://localhost:${JUICE_SHOP_PORT}}"

PORT=8900
[[ "${1:-}" == "--port" ]] && PORT="${2:?}"

cd "$ATTACKER_ROOT/live"
exec "$PYTHON" server.py --port "$PORT"
