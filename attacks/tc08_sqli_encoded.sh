#!/usr/bin/env bash
# TC-08  T1190  Encoded SQL injection  (sqlmap + tamper -> OWASP Juice Shop)
# SQL patterns obfuscated with URL-encoding / hex / inline comments.
# Expected: sql_injection_patterns_obfuscated_encoding_hex.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"

resolve_run_dir "${1:-}"
load_tc TC-08
log "TC-08 encoded SQL injection -> ${TC_DST}:${TC_DPORT}"

if real_tools_enabled; then
  assert_lab_target "$TC_DST"
  if have_tool sqlmap; then
    log "running sqlmap with tamper scripts against Juice Shop"
    sqlmap -u "http://${TC_DST}:${TC_DPORT}/rest/products/search?q=apple" \
      --batch --level=3 --risk=2 \
      --tamper=charencode,space2comment 2>>"$RUN_DIR/_tools.log" \
      >>"$RUN_DIR/_tools.log" || true
  else
    warn "sqlmap not installed; emitting normalized logs only"
  fi
fi

generate_logs TC-08
