#!/usr/bin/env bash
# TC-04  T1190  SQL injection  (sqlmap -> OWASP Juice Shop)
# Classic injection patterns in request parameters.
# Expected: sql_injection_patterns_in_request_parameters.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"

resolve_run_dir "${1:-}"
load_tc TC-04
log "TC-04 SQL injection -> ${TC_DST}:${TC_DPORT}"

if real_tools_enabled; then
  assert_lab_target "$TC_DST"
  if have_tool sqlmap; then
    log "running sqlmap against Juice Shop search endpoint"
    sqlmap -u "http://${TC_DST}:${TC_DPORT}/rest/products/search?q=apple" \
      --batch --level=2 --risk=2 2>>"$RUN_DIR/_tools.log" \
      >>"$RUN_DIR/_tools.log" || true
  else
    warn "sqlmap not installed; emitting normalized logs only"
  fi
fi

generate_logs TC-04
