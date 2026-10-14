#!/usr/bin/env bash
# baseline.sh — scan the target BEFORE attacking.
#
# Records the clean "before" snapshot (ports open, app health, 0 compromises).
# The dashboard shows this next to the post-attack "after" state so you can see
# exactly what changed. Run this once before ./attack.sh.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.sh"
export JUICE_URL="${JUICE_URL:-http://localhost:${JUICE_SHOP_PORT}}"
exec "$PYTHON" "$ATTACKER_ROOT/live/engine.py" baseline
