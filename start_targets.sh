#!/usr/bin/env bash
# start_targets.sh — start the vulnerable lab targets (the "shops").
#
# Starts OWASP Juice Shop (the main live target). DVWA is optional (--dvwa).
# These are intentionally vulnerable training apps; they run locally and are
# what the attacks hit.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.sh"

WANT_DVWA=0
[[ "${1:-}" == "--dvwa" ]] && WANT_DVWA=1

if ! command -v docker >/dev/null 2>&1; then
  echo "[targets] docker not found. Install docker, or set JUICE_URL to a running instance."
  exit 1
fi

echo "[targets] starting OWASP Juice Shop on :${JUICE_SHOP_PORT} …"
docker rm -f juice-shop >/dev/null 2>&1 || true
docker run -d --rm --name juice-shop -p "${JUICE_SHOP_PORT}:3000" \
  bkimminich/juice-shop:latest >/dev/null

echo -n "[targets] waiting for Juice Shop"
for _ in $(seq 1 60); do
  if curl -fsS "http://localhost:${JUICE_SHOP_PORT}/rest/admin/application-version" >/dev/null 2>&1; then
    echo " — up."; break
  fi
  echo -n "."; sleep 1
done

if [[ "$WANT_DVWA" == "1" ]]; then
  echo "[targets] starting DVWA on :${DVWA_PORT} …"
  docker rm -f dvwa >/dev/null 2>&1 || true
  docker run -d --rm --name dvwa -p "${DVWA_PORT}:80" vulnerables/web-dvwa:latest >/dev/null || true
fi

echo
echo "[targets] ready:"
echo "  Juice Shop : http://localhost:${JUICE_SHOP_PORT}"
[[ "$WANT_DVWA" == "1" ]] && echo "  DVWA       : http://localhost:${DVWA_PORT}  (login admin/password, security=low)"
echo
echo "Next:  ./baseline.sh   (scan the clean target)"
echo "       ./dashboard.sh  (open the console at :8900)"
echo "       ./attack.sh     (run the real attacks)"
