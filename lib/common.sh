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
