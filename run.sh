#!/usr/bin/env bash
# ==========================================================================
# run.sh  -  Orchestrator. Runs the recon phases in order against your scope.
#
#   ./run.sh                 # full recon chain (AD recon needs read-only creds)
#   ./run.sh 00 02 04        # run only selected phases (forces re-run)
#   ./run.sh menu            # interactive menu: pick a phase, then a sub-task
#
# RECON-ONLY: no password spraying, no credential brute force, no service-
# disruptive actions. Authenticated phases require read-only domain creds.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh

BANNER=$(cat <<'B'
  ___ _  _ _____ ___ ___ _  _   _   _    ___ ___ ___ ___  _  _
 |_ _| \| |_   _| __| _ \ \| | /_\ | |  | _ \ __/ __/ _ \| \| |
  | || .` | | | | _||   / .` |/ _ \| |__|   / _| (_| (_) | .` |
 |___|_|\_| |_| |___|_|_\_|\_/_/ \_\____|_|_\___\___\___/|_|\_|
              internal network recon kit  (recon-only)
B
)
printf '%s%s%s\n' "$C_CYN" "$BANNER" "$C_RST"

# ---- Authorisation / scope gate ------------------------------------------
require_scope
N=$(clean_scope | wc -l)
warn "Scope: $N entries from '$SCOPE_FILE'. This runs ACTIVE recon scanning against them."
warn "Only proceed if you have WRITTEN authorisation covering every target."
read -rp "Type the word AUTHORISED to continue: " a
[[ "$a" == "AUTHORISED" ]] || { err "Not confirmed. Exiting."; exit 1; }

# ---- Run directory (STATIC — re-runs resume from the first unfinished phase)
# A fixed directory means a second invocation reuses prior output: any phase
# whose '.done' marker is present is skipped, so e.g. if 00/02/03 finished last
# time, the run picks up at 04. Force a phase to re-run by naming it explicitly
# (./run.sh 04) or by deleting its marker; start completely fresh by removing
# the whole run dir ($OUTPUT_BASE/run).
export RUN="$OUTPUT_BASE/run"
mkdir -p "$RUN"
cp "$SCOPE_FILE" "$RUN/scope.txt"
ok "Output directory: $RUN"
exec > >(tee -a "$RUN/run.log") 2>&1   # full transcript

# ---- Phase registry -------------------------------------------------------
PHASE_ORDER=(00 02 03 04 05 06 07 08)
declare -A MODULE=(
  [00]=00-prep.sh        [02]=02-portscan.sh   [03]=03-enum-smb-ad.sh
  [04]=04-enum-web.sh    [05]=05-enum-db.sh    [06]=06-ad-recon.sh
  [07]=07-vuln-scan.sh   [08]=08-report.sh
)
declare -A PHASE_DESC=(
  [00]="Preflight & live-host list"   [02]="Port & service scan"
  [03]="SMB / AD enumeration"         [04]="Web enumeration"
  [05]="Database enumeration"         [06]="AD recon (roasting / BloodHound)"
  [07]="Vulnerability detection"      [08]="Consolidated reporting"
)

# Menu styling (bold tracks whether colours are enabled; BAR = left accent).
C_BLD=''; [[ -n "$C_CYN" ]] && C_BLD=$'\e[1m'
BAR="${C_CYN}┃${C_RST}"

# Run one phase (all its sub-tasks). Writes a .done marker on success.
run_phase() {
  local p="$1" script="${MODULE[$1]:-}"
  [[ -n "$script" ]] || { warn "Unknown phase '$p' — skipping."; return 0; }
  phase "PHASE $p — $script"
  if RUN="$RUN" bash "./$script"; then
    touch "$RUN/.done-$p"
  else
    warn "Phase $p exited non-zero — not marking complete; it will retry next run."
  fi
}

# Run a list of phases. In resume mode (explicit=false) phases with a .done
# marker are skipped; explicit selection always re-runs.
run_phases() {
  local explicit="$1"; shift
  local p
  for p in "$@"; do
    [[ -n "${MODULE[$p]:-}" ]] || { warn "Unknown phase '$p' — skipping."; continue; }
    if [[ "$explicit" == "false" && -f "$RUN/.done-$p" ]]; then
      ok "PHASE $p — ${MODULE[$p]} already complete — skipping (rm $RUN/.done-$p to redo)."
      continue
    fi
    run_phase "$p"
  done
}

# Run a single sub-task within a phase (manual mode; no .done marker).
run_phase_task() {
  phase "PHASE $1 — sub-task '$2'"
  TASK_ONLY="$2" RUN="$RUN" bash "./${MODULE[$1]}" || warn "Sub-task '$2' exited non-zero."
}

# Print a phase's sub-tasks as "id<TAB>description" lines (no side effects).
phase_tasks() {
  TASK_LIST=1 RUN="$RUN" bash "./${MODULE[$1]}" 2>/dev/null \
    | awk -F'\t' '$1=="TASK"{print $2"\t"$3}'
}

print_summary() {
  ok "All output under: $RUN"
  echo
  log "Start with the consolidated report, then drill into the evidence:"
  echo "  - $RUN/REPORT.md                     (consolidated recon summary, Markdown)"
  echo "  - $RUN/nmap_report.html              (infrastructure intel + risk scores)"
  echo "  - $RUN/web_report.html               (web vulnerabilities, severity-ranked)"
  echo "  - $RUN/07-vuln/*_summary.txt         (EternalBlue/Zerologon/etc. detections)"
  echo "  - $RUN/03-smb-ad/shares*             (readable shares, null sessions)"
  echo "  - $RUN/04-web/nuclei.txt             (web findings)"
  echo "  - $RUN/06-ad-recon/*hashes.txt       (crack OFFLINE w/ hashcat)"
  echo "  - $RUN/05-db/db_nse.nmap             (empty-password DBs)"
}

# ---- Interactive sub-task menu: phase 00..08 -> sub-task -> run -----------
task_submenu() {
  local p="$1" lines ids=() descs=() id desc i sel
  lines=$(phase_tasks "$p")
  if [[ -z "$lines" ]]; then warn "No sub-tasks found for phase $p."; return 0; fi
  while IFS=$'\t' read -r id desc; do
    [[ -n "$id" ]] && { ids+=("$id"); descs+=("$desc"); }
  done <<<"$lines"
  while true; do
    printf '\n %s\n' "$BAR"
    printf ' %s  %s%sPhase %s%s  %s%s%s\n' "$BAR" "$C_BLD" "$C_CYN" "$p" "$C_RST" "$C_DIM" "${PHASE_DESC[$p]}" "$C_RST"
    printf ' %s  %spick a sub-task to run on its own%s\n' "$BAR" "$C_DIM" "$C_RST"
    printf ' %s\n' "$BAR"
    for i in "${!ids[@]}"; do
      printf ' %s   %s%2d%s  %s%-13s%s %s%s%s\n' \
        "$BAR" "$C_YEL" "$((i+1))" "$C_RST" "$C_GRN" "${ids[$i]}" "$C_RST" "$C_DIM" "${descs[$i]}" "$C_RST"
    done
    printf ' %s\n' "$BAR"
    printf ' %s   %sa%s  %s▶%s run the whole phase %s\n' "$BAR" "$C_YEL" "$C_RST" "$C_GRN" "$C_RST" "$p"
    printf ' %s   %sb%s  %s◂%s back to phase list\n'     "$BAR" "$C_YEL" "$C_RST" "$C_BLU" "$C_RST"
    printf ' %s\n' "$BAR"
    read -rp "$(printf ' %stask ▸%s ' "$C_CYN" "$C_RST")" sel || { echo; return 0; }
    case "$sel" in
      b|B|"") return 0 ;;
      a|A)    run_phase "$p" ;;
      *)
        if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel>=1 && sel<=${#ids[@]} )); then
          run_phase_task "$p" "${ids[$((sel-1))]}"
        else
          warn "Invalid selection: '$sel'"
        fi ;;
    esac
  done
}

interactive_menu() {
  local p choice
  while true; do
    printf '\n %s\n' "$BAR"
    printf ' %s  %s%sCEDZO%s %s· internal network recon kit%s\n' "$BAR" "$C_BLD" "$C_CYN" "$C_RST" "$C_DIM" "$C_RST"
    printf ' %s  %spick a phase, then a sub-task — or run everything%s\n' "$BAR" "$C_DIM" "$C_RST"
    printf ' %s\n' "$BAR"
    for p in "${PHASE_ORDER[@]}"; do
      if [[ -f "$RUN/.done-$p" ]]; then
        printf ' %s   %s✓%s  %s%s%s  %s\n' "$BAR" "$C_GRN" "$C_RST" "$C_CYN" "$p" "$C_RST" "${PHASE_DESC[$p]}"
      else
        printf ' %s   %s·%s  %s%s%s  %s\n' "$BAR" "$C_DIM" "$C_RST" "$C_CYN" "$p" "$C_RST" "${PHASE_DESC[$p]}"
      fi
    done
    printf ' %s\n' "$BAR"
    printf ' %s   %sa%s  %s▶%s run ALL phases  %s(full chain, resume-aware)%s\n' \
      "$BAR" "$C_YEL" "$C_RST" "$C_GRN" "$C_RST" "$C_DIM" "$C_RST"
    printf ' %s   %sq%s  %s✕%s quit\n' "$BAR" "$C_YEL" "$C_RST" "$C_RED" "$C_RST"
    printf ' %s\n' "$BAR"
    read -rp "$(printf ' %sphase ▸%s ' "$C_CYN" "$C_RST")" choice || { echo; return 0; }
    case "$choice" in
      q|Q|"") return 0 ;;
      a|A)    run_phases false "${PHASE_ORDER[@]}" ;;
      *)
        if [[ -n "${MODULE[$choice]:-}" ]]; then task_submenu "$choice"
        else warn "Unknown phase: '$choice'"; fi ;;
    esac
  done
}

# ---- Dispatch -------------------------------------------------------------
if [[ "${1:-}" =~ ^(menu|-i|--menu|--interactive)$ ]]; then
  interactive_menu
  echo
  print_summary
  exit 0
fi

# Explicit phase selection forces those phases to re-run (ignoring markers);
# the default full chain resumes, skipping already-completed phases.
EXPLICIT=true
PHASES=("$@")
[[ ${#PHASES[@]} -eq 0 ]] && { PHASES=("${PHASE_ORDER[@]}"); EXPLICIT=false; }

START=$(date +%s)
run_phases "$EXPLICIT" "${PHASES[@]}"
DUR=$(( $(date +%s) - START ))
phase "DONE in $((DUR/60))m $((DUR%60))s"
print_summary
