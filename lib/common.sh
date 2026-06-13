#!/usr/bin/env bash
# ==========================================================================
# lib/common.sh  -  Shared functions sourced by every module.
# ==========================================================================

# ---- Colours --------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
  C_BLU=$'\e[34m'; C_CYN=$'\e[36m'; C_DIM=$'\e[2m'; C_RST=$'\e[0m'
else
  C_RED=; C_GRN=; C_YEL=; C_BLU=; C_CYN=; C_DIM=; C_RST=
fi

log()   { printf '%s[*]%s %s\n'  "$C_BLU" "$C_RST" "$*"; }
ok()    { printf '%s[+]%s %s\n'  "$C_GRN" "$C_RST" "$*"; }
warn()  { printf '%s[!]%s %s\n'  "$C_YEL" "$C_RST" "$*"; }
err()   { printf '%s[x]%s %s\n'  "$C_RED" "$C_RST" "$*" >&2; }
phase() { printf '\n%s===== %s =====%s\n' "$C_CYN" "$*" "$C_RST"; }

# Log a command line then run it, tee'ing output to a logfile.
run() {
  local logfile="$1"; shift
  printf '%s$ %s%s\n' "$C_DIM" "$*" "$C_RST"
  printf '$ %s\n' "$*" >> "$logfile"
  "$@" 2>&1 | tee -a "$logfile"
  return "${PIPESTATUS[0]}"
}

have() { command -v "$1" >/dev/null 2>&1; }

# Resolve the CrackMapExec / NetExec binary (name changed across releases).
nxc_bin() {
  if   have nxc;          then echo nxc
  elif have netexec;      then echo netexec
  elif have crackmapexec; then echo crackmapexec
  else return 1; fi
}

# Resolve ProjectDiscovery's httpx (the HTTP probe/fingerprint tool the kit
# uses), NOT the unrelated Python `httpx` HTTP-client CLI that shares the name.
# On Kali the PD build is the `httpx-toolkit` package/binary, so prefer that;
# otherwise accept a bare `httpx` only if its help advertises PD-specific flags
# (so a python-httpx on PATH is correctly rejected and the phase degrades).
HTTPX_BIN=""
httpx_bin() {
  [[ -n "$HTTPX_BIN" ]] && { echo "$HTTPX_BIN"; return 0; }
  if have httpx-toolkit; then HTTPX_BIN=httpx-toolkit
  elif have httpx && httpx -h 2>&1 | grep -qiE 'projectdiscovery|tech-detect'; then HTTPX_BIN=httpx
  else return 1; fi
  echo "$HTTPX_BIN"
}

# Run up to $THREADS jobs in parallel from stdin (one arg per line).
# Usage:  cat hosts | parallelize my_func
parallelize() {
  local fn="$1"
  export -f "$fn" 2>/dev/null || true
  xargs -P "${THREADS:-10}" -I{} bash -c "$fn"' "$@"' _ {}
}

require_scope() {
  [[ -s "$SCOPE_FILE" ]] || { err "Scope file '$SCOPE_FILE' missing/empty."; exit 1; }
}

# Strip comments/blanks from scope file.
clean_scope() { grep -vE '^\s*(#|$)' "$SCOPE_FILE"; }

# ---- Sub-task framework ---------------------------------------------------
# Each phase splits its work into named sub-tasks (bash functions) registered
# with `task`. `run_tasks` then either:
#   * runs every registered task in order   (normal phase run; ./run.sh path),
#   * runs a single task                     (TASK_ONLY=<id>; menu "run task"),
#   * prints the task catalogue and exits    (TASK_LIST=1;     menu listing).
# This keeps the full-chain behaviour identical while enabling manual,
# per-task execution from the interactive menu.
_TASK_IDS=(); declare -A _TASK_DESC=(); declare -A _TASK_FN=()

task() {                       # task <id> <description> <function-name>
  _TASK_IDS+=("$1"); _TASK_DESC["$1"]="$2"; _TASK_FN["$1"]="$3"
}

# True when the phase was launched only to enumerate its tasks for the menu.
# Phases use this to skip their "prerequisite missing -> exit" gates so the
# catalogue can be listed before earlier phases have produced their output.
task_listing() { [[ "${TASK_LIST:-0}" == "1" ]]; }

run_tasks() {
  (( ${#_TASK_IDS[@]} )) || return 0
  local id
  if task_listing; then
    # Sentinel-prefixed, tab-separated so the menu can parse cleanly even amid
    # other stdout noise from phase setup.
    for id in "${_TASK_IDS[@]}"; do printf 'TASK\t%s\t%s\n' "$id" "${_TASK_DESC[$id]}"; done
    return 0
  fi
  local only="${TASK_ONLY:-}" ran=0
  for id in "${_TASK_IDS[@]}"; do
    [[ -n "$only" && "$only" != "$id" ]] && continue
    ran=1
    phase "▸ $id — ${_TASK_DESC[$id]}"
    "${_TASK_FN[$id]}" || warn "sub-task '$id' exited non-zero (continuing)."
  done
  if [[ -n "$only" && "$ran" -eq 0 ]]; then err "No such sub-task: '$only'"; return 1; fi
  return 0
}

# ---- AI analysis layer ----------------------------------------------------
# Sourced last so every phase gets the ai_* helpers / bridges. No-ops unless
# AI_PROVIDER=anthropic and ANTHROPIC_API_KEY is set (see config.sh).
#
# The per-phase analysis functions are mode-specific (internal recon vs external
# attack-surface), so we source the matching library. KIT_MODE is exported by
# run.sh; a standalone phase invocation defaults to internal.
if [[ "${KIT_MODE:-internal}" == "external" ]]; then
  source "$(dirname "${BASH_SOURCE[0]}")/ai-ext.sh"
else
  source "$(dirname "${BASH_SOURCE[0]}")/ai.sh"
fi

# ---- OWASP ZAP web-scan layer ---------------------------------------------
# Provides zap_web_scan (spider + passive + active) for the web phases.
source "$(dirname "${BASH_SOURCE[0]}")/zap.sh"
