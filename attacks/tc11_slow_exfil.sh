#!/usr/bin/env bash
# TC-11  T1048  Low-and-slow exfiltration  (Caldera timing -> outbound)
# Data exfiltration broken into small chunks spread over hours.
# Expected: data_exfiltration_spread_over_hours.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"

resolve_run_dir "${1:-}"
load_tc TC-11
log "TC-11 low-and-slow exfiltration from ${TC_SRC} (spread over ${TC_WINDOW}s in logs)"

if real_tools_enabled; then
  # Caldera drives the throttled exfil ability from the compromised lab host.
  warn "Caldera-driven throttled exfil hook not wired; emitting normalized logs only"
fi

generate_logs TC-11
