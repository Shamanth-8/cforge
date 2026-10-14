#!/usr/bin/env bash
# run_live.sh — all-in-one: start target, baseline, dashboard, and attack.
#
# Convenience wrapper that runs the whole live demo in one command. For step by
# step control use the individual commands instead:
#   ./start_targets.sh   ./baseline.sh   ./dashboard.sh   ./attack.sh
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.sh"
export JUICE_URL="${JUICE_URL:-http://localhost:${JUICE_SHOP_PORT}}"

PORT=8900
START_TARGET=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --no-target) START_TARGET=0; shift ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

[[ "$START_TARGET" == "1" ]] && bash "$ATTACKER_ROOT/start_targets.sh" || true

echo "[live] baseline scan (before)…"
"$PYTHON" "$ATTACKER_ROOT/live/engine.py" baseline || true

echo "[live] launching dashboard on :${PORT} (background)…"
( cd "$ATTACKER_ROOT/live" && "$PYTHON" server.py --port "$PORT" ) &
DASH=$!
sleep 2

echo "[live] running real attacks…"
"$PYTHON" "$ATTACKER_ROOT/live/engine.py" attack || true

echo "[live] attacks done. Dashboard still running at http://localhost:${PORT}/ (Ctrl-C to stop)."
wait "$DASH"
