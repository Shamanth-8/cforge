#!/usr/bin/env bash
# Stage the SSH authentication target.
#
# This is the authentication target for the Hydra brute-force (TC-01) and
# password-spray (TC-02) test cases. In a real lab this is a throwaway VM or a
# second host on the isolated lab subnet, with a set of weak test accounts that
# exist only to be attacked and then discarded.
#
# This script does NOT create real OS accounts on the host it runs on. It only
# writes the test-account roster (names + deliberately weak passwords) that the
# attack scripts reference. Provision these on a disposable lab VM yourself.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/config.sh"

ROSTER="$(dirname "${BASH_SOURCE[0]}")/accounts.txt"

cat > "$ROSTER" <<'EOF'
# Disposable lab test accounts for the SSH authentication target.
# Format: username:password   (weak on purpose; lab-only, never real creds)
root:toor
admin:admin123
deploy:deploy
user01:Summer2024
user02:Password1
user03:welcome
user04:letmein
user05:changeme
user06:qwerty123
user07:test1234
user08:dragon
user09:football
user10:iloveyou
user11:monkey123
user12:abc12345
user13:passw0rd
user14:sunshine
user15:master123
user16:shadow123
EOF

echo "[target] wrote lab SSH account roster: $ROSTER"
echo "[target] Provision these on a disposable VM at ${SSH_HOST} to attack a live host."
echo "[target] (ATTACKER still produces normalized logs without a live target.)"
