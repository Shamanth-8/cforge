#!/usr/bin/env bash
# Launch OWASP Juice Shop, the vulnerable web app / REST API target.
# Juice Shop is a purpose-built, intentionally insecure training application.
# It runs on the isolated lab subnet and is destroyed during the attack run.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/config.sh"

NAME="juice-shop"
PORT="${JUICE_SHOP_PORT}"

if command -v docker >/dev/null 2>&1; then
  echo "[target] starting Juice Shop via docker on port ${PORT}"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --rm --name "$NAME" -p "${PORT}:3000" \
    bkimminich/juice-shop:latest
  echo "[target] Juice Shop: http://localhost:${PORT}"
else
  echo "[target] docker not found."
  echo "[target] Install, then run:"
  echo "         docker run -d --rm --name ${NAME} -p ${PORT}:3000 bkimminich/juice-shop:latest"
  echo "[target] (ATTACKER still produces normalized logs without a live target.)"
fi
