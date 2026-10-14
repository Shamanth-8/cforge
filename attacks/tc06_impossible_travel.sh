#!/usr/bin/env bash
# TC-06  T1078  Impossible travel  (Caldera -> Juice Shop account)
# Same account active from two distant locations in an impossible time.
# Expected: same_account_distant_locations_impossible_time.
# The two source IPs are RFC5737 documentation addresses standing in for two
# far-apart public origins; map them in ThreatLoop's geo stub.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"

resolve_run_dir "${1:-}"
load_tc TC-06
log "TC-06 impossible travel for account on ${TC_DST}"

if real_tools_enabled; then
  warn "Caldera-driven login replay hook not wired; emitting normalized logs only"
fi

generate_logs TC-06
