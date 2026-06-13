#!/usr/bin/env bash
# ==========================================================================
# 01-prep.sh  -  Preflight checks + build live_hosts.txt from scope.txt.
#                All IPs in scope are treated as reachable; no ping gating.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
require_scope
RUN="${RUN:?RUN not set — launch via run.sh}"

phase "Preflight"

# ---- Sub-task: scope validation ----------------------------------------------
t_validate_scope() {
  log "Validating scope.txt"
  local bad
  bad=$(clean_scope | grep -vE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' || true)
  if [[ -n "$bad" ]]; then
    err "scope.txt contains non-IP lines (CIDRs are fine; hostnames are not):"
    echo "$bad"
    exit 1
  fi
  ok "Scope entries: $(clean_scope | wc -l)"
}

# ---- Sub-task: tool checks ---------------------------------------------------
# Tool list comes from the single source of truth (lib/tools.sh / kit_tools), so
# this preflight and 00-setup can never drift. Required tools hard-fail; optional
# ones just warn (their phases skip gracefully).
t_check_tools() {
  log "Checking tools (source: lib/tools.sh)"
  local bin apt hint flag missing_req=() missing_opt=()
  while IFS=':' read -r bin apt hint flag; do
    [[ -n "$bin" ]] || continue
    have "$bin" && continue
    if [[ "$flag" == "req" ]]; then missing_req+=("$bin"); else missing_opt+=("$bin"); fi
  done < <(kit_tools internal)
  # sudo is required for the privileged scans (sudo nmap -sS / masscan).
  have sudo || missing_req+=("sudo")

  if [[ ${#missing_req[@]} -gt 0 ]]; then
    err "Missing REQUIRED tools: ${missing_req[*]}"
    err "Install with: ./00-setup.sh"
    exit 1
  fi
  [[ ${#missing_opt[@]} -gt 0 ]] && warn "Optional tools missing (their phases will skip): ${missing_opt[*]}"
  # Name-tolerant resolvers (handled outside kit_tools).
  httpx_bin >/dev/null 2>&1 || warn "ProjectDiscovery httpx not found (install httpx-toolkit) — web fingerprint degrades."
  nxc_bin   >/dev/null 2>&1 || warn "NetExec/CrackMapExec not found — SMB/AD enumeration degrades."
  ok "Tool check complete"
}

# ---- Sub-task: build live host list ------------------------------------------
t_build_hosts() {
  log "Building live_hosts.txt from scope.txt"
  clean_scope | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$RUN/live_hosts.txt"
  ok "$(wc -l < "$RUN/live_hosts.txt") hosts loaded -> $RUN/live_hosts.txt"
  column "$RUN/live_hosts.txt" 2>/dev/null || cat "$RUN/live_hosts.txt"
}

task validate_scope "Validate scope.txt (IP/CIDR syntax)"          t_validate_scope
task check_tools    "Check required + optional tools are installed" t_check_tools
task build_hosts    "Build live_hosts.txt from scope"               t_build_hosts
run_tasks
