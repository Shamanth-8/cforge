#!/usr/bin/env bash
# Launch DVWA (Damn Vulnerable Web Application), the SQL injection /
# authentication / brute-force target. DVWA is a deliberately vulnerable
# training app. It runs on the isolated lab subnet and is destroyed during
# the attack run.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/config.sh"

NAME="dvwa"
PORT="${DVWA_PORT}"

if command -v docker >/dev/null 2>&1; then
  echo "[target] starting DVWA via docker on port ${PORT}"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --rm --name "$NAME" -p "${PORT}:80" vulnerables/web-dvwa:latest
  echo "[target] DVWA: http://localhost:${PORT}  (login admin/password, set security=low)"
else
  echo "[target] docker not found."
  echo "[target] Install, then run:"
  echo "         docker run -d --rm --name ${NAME} -p ${PORT}:80 vulnerables/web-dvwa:latest"
  echo "[target] (ATTACKER still produces normalized logs without a live target.)"
fi
