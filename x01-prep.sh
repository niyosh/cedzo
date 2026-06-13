#!/usr/bin/env bash
# ==========================================================================
# 01-prep.sh  -  Preflight checks + normalise scope into IP and DOMAIN target
#                lists. Scope may mix public IPs / ranges / CIDRs and root
#                domains; this phase separates them so later phases can treat
#                each kind appropriately (OSINT expands domains -> more IPs).
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
require_scope
RUN="${RUN:?RUN not set — launch via run.sh}"

phase "Preflight"

IP_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
RANGE_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}$'
DOMAIN_RE='^([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

# Warn (do not fail) on entries that look like RFC1918 private space — this kit
# targets PUBLIC assets; private ranges usually indicate a copy/paste mistake.
_is_private() { grep -qE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)' <<<"$1"; }

# ---- Sub-task: scope validation + classification -------------------------
t_validate_scope() {
  log "Validating + classifying scope.txt (IPs/ranges/CIDRs vs domains)"
  local line bad=() priv=()
  : > "$RUN/ip_targets.txt"; : > "$RUN/domain_targets.txt"
  while read -r line; do
    [[ -n "$line" ]] || continue
    if [[ "$line" =~ $IP_RE || "$line" =~ $RANGE_RE ]]; then
      echo "$line" >> "$RUN/ip_targets.txt"
      _is_private "$line" && priv+=("$line")
    elif [[ "$line" =~ $DOMAIN_RE ]]; then
      echo "${line,,}" >> "$RUN/domain_targets.txt"
    else
      bad+=("$line")
    fi
  done < <(clean_scope)

  if [[ ${#bad[@]} -gt 0 ]]; then
    err "scope.txt has lines that are neither IP/range/CIDR nor a domain:"
    printf '  %s\n' "${bad[@]}"
    exit 1
  fi
  if [[ ${#priv[@]} -gt 0 ]]; then
    warn "Scope contains PRIVATE/RFC1918 addresses — this is an EXTERNAL kit (use cedzo for internal):"
    printf '  %s\n' "${priv[@]}"
  fi
  sort -u -o "$RUN/ip_targets.txt"     "$RUN/ip_targets.txt"     2>/dev/null || true
  sort -u -o "$RUN/domain_targets.txt" "$RUN/domain_targets.txt" 2>/dev/null || true
  # If TARGET_DOMAIN is set in config, ensure it is also a domain target.
  if [[ -n "${TARGET_DOMAIN:-}" ]]; then
    grep -qxF "${TARGET_DOMAIN,,}" "$RUN/domain_targets.txt" 2>/dev/null \
      || echo "${TARGET_DOMAIN,,}" >> "$RUN/domain_targets.txt"
  fi
  ok "IP/range/CIDR targets: $(_ai_count "$RUN/ip_targets.txt")  |  Domain targets: $(_ai_count "$RUN/domain_targets.txt")"
}

# ---- Sub-task: tool checks -----------------------------------------------
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
  done < <(kit_tools external)

  if [[ ${#missing_req[@]} -gt 0 ]]; then
    err "Missing REQUIRED tools: ${missing_req[*]}"
    err "Install with: KIT_MODE=external ./00-setup.sh"
    exit 1
  fi
  [[ ${#missing_opt[@]} -gt 0 ]] && warn "Optional tools missing (their phases will skip): ${missing_opt[*]}"
  # Name-tolerant resolver (handled outside kit_tools).
  httpx_bin >/dev/null 2>&1 || warn "ProjectDiscovery httpx not found (install httpx-toolkit) — web fingerprint degrades."
  ok "Tool check complete"
}

# ---- Sub-task: seed live host list from the IP targets --------------------
# live_hosts.txt starts as the explicit IP scope. Phase 02 (OSINT) resolves
# domain targets + discovered subdomains and APPENDS their public IPs here, so
# the active scan phases pick up the full footprint automatically.
t_seed_hosts() {
  log "Seeding live_hosts.txt from IP targets (domains are added by phase 02)"
  cp "$RUN/ip_targets.txt" "$RUN/live_hosts.txt" 2>/dev/null || : > "$RUN/live_hosts.txt"
  if [[ -s "$RUN/live_hosts.txt" ]]; then
    sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n "$RUN/live_hosts.txt" -o "$RUN/live_hosts.txt" 2>/dev/null \
      || sort -u "$RUN/live_hosts.txt" -o "$RUN/live_hosts.txt"
  fi
  ok "$(_ai_count "$RUN/live_hosts.txt") IP target(s) seeded -> $RUN/live_hosts.txt"
  [[ -s "$RUN/live_hosts.txt" ]] && { column "$RUN/live_hosts.txt" 2>/dev/null || cat "$RUN/live_hosts.txt"; }
  [[ -s "$RUN/domain_targets.txt" ]] && log "Domain targets pending OSINT expansion: $(_ai_count "$RUN/domain_targets.txt")"
}

task validate_scope "Validate + classify scope (IP/CIDR vs domain)"   t_validate_scope
task check_tools    "Check required + optional tools are installed"   t_check_tools
task seed_hosts     "Seed live_hosts.txt from IP targets"             t_seed_hosts
run_tasks
