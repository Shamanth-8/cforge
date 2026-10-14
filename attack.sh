#!/usr/bin/env bash
# attack.sh — run the real attacks against the live target.
#
# Executes all 11 attacks for real and saves the run to disk. If the dashboard
# (./dashboard.sh) is open at :8900, it updates live as this runs. Results
# persist, so you can close this, refresh the dashboard, and still see them.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.sh"
export JUICE_URL="${JUICE_URL:-http://localhost:${JUICE_SHOP_PORT}}"
exec "$PYTHON" "$ATTACKER_ROOT/live/engine.py" attack
