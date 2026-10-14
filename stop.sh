#!/usr/bin/env bash
# stop.sh — stop EVERYTHING in one command.
#
# Stops the local target websites (OWASP Juice Shop :3000, DVWA :80) and the
# attack dashboard (:8900). Attacks are short-lived and stop on their own; this
# shuts down the long-running services.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.sh"

echo "[stop] stopping the dashboard server…"
pkill -f "server.py --port" 2>/dev/null || true
pkill -f "live/server.py"   2>/dev/null || true

if command -v docker >/dev/null 2>&1; then
  for c in juice-shop dvwa; do
    if [ -n "$(docker ps -q -f "name=^${c}$" 2>/dev/null)" ]; then
      echo "[stop] stopping container: $c"
      docker rm -f "$c" >/dev/null 2>&1 || true
    fi
  done
fi

echo "[stop] done — Juice Shop (:3000), DVWA (:80), and the dashboard (:8900) are stopped."
echo "[stop] (saved runs and history remain on disk; use the dashboard to clear them.)"
