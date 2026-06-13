#!/usr/bin/env bash
# ==========================================================================
# tools/check.sh  -  Developer guardrail: lint + smoke-test the kit.
#
#   tools/check.sh           # run everything (syntax + shellcheck + smoke)
#   tools/check.sh syntax    # bash -n on every script
#   tools/check.sh lint      # shellcheck (skipped with a note if not installed)
#   tools/check.sh smoke     # list every phase's sub-tasks in both modes
#
# Wrapped by the Makefile, but works standalone (no `make` needed). Exits
# non-zero if any check fails — suitable for CI / a pre-commit hook.
# ==========================================================================
set -uo pipefail
cd "$(dirname "$0")/.."   # kit root

C_G=$'\e[32m'; C_R=$'\e[31m'; C_Y=$'\e[33m'; C_0=$'\e[0m'
pass=0; fail=0
ok()   { printf '%s  ok%s  %s\n'   "$C_G" "$C_0" "$*"; pass=$((pass+1)); }
bad()  { printf '%s FAIL%s %s\n'   "$C_R" "$C_0" "$*"; fail=$((fail+1)); }
note() { printf '%s  ..%s  %s\n'   "$C_Y" "$C_0" "$*"; }

ALL_SH=( *.sh lib/*.sh tools/*.sh )

do_syntax() {
  printf '\n== syntax (bash -n) ==\n'
  local f
  for f in "${ALL_SH[@]}"; do
    if bash -n "$f" 2>/tmp/_cberr; then ok "$f"; else bad "$f"; cat /tmp/_cberr; fi
  done
}

do_lint() {
  printf '\n== shellcheck ==\n'
  if ! command -v shellcheck >/dev/null 2>&1; then
    note "shellcheck not installed — skipping (apt install shellcheck). Not counted as failure."
    return 0
  fi
  local f
  for f in "${ALL_SH[@]}"; do
    if shellcheck -x "$f"; then ok "$f"; else bad "shellcheck: $f"; fi
  done
}

# Smoke: every phase must list its sub-tasks (TASK_LIST=1) cleanly in both modes.
# Needs a throwaway scope + RUN dir; nothing is actually scanned.
do_smoke() {
  printf '\n== smoke (phase task listing, both modes) ==\n'
  local tmp scope mode script ids
  tmp=$(mktemp -d); scope="$tmp/scope.txt"; printf '203.0.113.10\n' > "$scope"
  export SCOPE_FILE="$scope" RUN="$tmp/run"; mkdir -p "$RUN"
  printf 'http://203.0.113.10\n' > "$RUN/web_urls.txt"
  printf '203.0.113.10\n' > "$RUN/live_hosts.txt"
  for mode in internal external; do
    local prefix=""; [[ "$mode" == external ]] && prefix="x"
    for script in "${prefix}0"{1..9}-*.sh; do
      [[ -f "$script" ]] || continue
      ids=$(KIT_MODE="$mode" TASK_LIST=1 bash "./$script" 2>/dev/null \
            | awk -F'\t' '$1=="TASK"{c++} END{print c+0}')
      if [[ "${ids:-0}" -ge 1 ]]; then ok "$mode/$script ($ids tasks)"; else bad "$mode/$script listed no tasks"; fi
    done
  done
  rm -rf "$tmp"
}

case "${1:-all}" in
  syntax) do_syntax ;;
  lint)   do_lint ;;
  smoke)  do_smoke ;;
  all)    do_syntax; do_lint; do_smoke ;;
  *) echo "usage: $0 [all|syntax|lint|smoke]" >&2; exit 2 ;;
esac

printf '\n== summary: %s passed, %s failed ==\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
