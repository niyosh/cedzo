#!/usr/bin/env bash
# ==========================================================================
# run.sh  -  Unified orchestrator. Runs the recon phases in order against your
#            scope, in one of two MODES:
#
#     internal  -  internal network recon            (read-only creds optional)
#     external  -  external attack-surface recon     (public IPs / root domains)
#
#   ./run.sh                      # ask internal/external, then full chain
#   ./run.sh internal             # internal full chain
#   ./run.sh external             # external full chain
#   ./run.sh internal 01 02 04    # run only selected phases (forces re-run)
#   ./run.sh external menu        # interactive menu: pick a phase, then a task
#   KIT_MODE=external ./run.sh    # mode via environment instead of argument
#
# RECON-ONLY: no exploitation, no password spraying, no credential brute force,
# no service-disruptive actions. Authenticated internal phases require read-only
# domain creds. Each mode writes to its own run dir, so the two never collide.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"

# ---- Mode selection -------------------------------------------------------
# Priority: explicit first argument > KIT_MODE env > interactive prompt.
normalise_mode() {
  case "${1,,}" in
    internal|int|i) echo internal ;;
    external|ext|e|x) echo external ;;
    *) echo "" ;;
  esac
}

MODE=""
if [[ $# -gt 0 ]]; then
  m=$(normalise_mode "$1")
  [[ -n "$m" ]] && { MODE="$m"; shift; }
fi
[[ -z "$MODE" && -n "${KIT_MODE:-}" ]] && MODE=$(normalise_mode "$KIT_MODE")

if [[ -z "$MODE" ]]; then
  printf 'Select engagement type:\n'
  printf '  1) internal  — internal network recon\n'
  printf '  2) external  — external attack-surface recon\n'
  read -rp 'Mode [1/2]: ' msel
  case "$msel" in
    1|internal|int|i) MODE=internal ;;
    2|external|ext|e|x) MODE=external ;;
    *) echo "Unrecognised choice: '$msel'." >&2; exit 1 ;;
  esac
fi

export KIT_MODE="$MODE"
source ./config.sh
source ./lib/common.sh

# ---- Per-mode presentation, registry, warnings, summary -------------------
if [[ "$KIT_MODE" == "external" ]]; then
  BANNER=$(cat <<'B'
  ___ _  _ _____ ___ ___ _  _   _   _      ___ ___ ___ ___  _  _
 | __| |/ /_   _| __| _ \ \| | /_\ | |    | _ \ __/ __/ _ \| \| |
 | _|| ' <  | | | _||   / .` |/ _ \| |__  |   / _| (_| (_) | .` |
 |___|_|\_\ |_| |___|_|_\_|\_/_/ \_\____| |_|_\___\___\___/|_|\_|
            external attack-surface recon kit  (recon-only)
B
)
  MENU_TITLE='EXDZO · external attack-surface recon kit'
  PHASE_ORDER=(01 02 03 04 05 06 07 08 09)
  declare -A MODULE=(
    [01]=x01-prep.sh        [02]=x02-osint.sh           [03]=x03-portscan.sh
    [04]=x04-enum-web.sh    [05]=x05-exposure.sh        [06]=x06-takeover-cloud.sh
    [07]=x07-vuln-scan.sh   [08]=x08-report.sh          [09]=x09-xlsx-report.sh
  )
  declare -A PHASE_DESC=(
    [01]="Preflight & target normalisation"  [02]="OSINT / passive recon"
    [03]="External port & service scan"      [04]="Web enumeration"
    [05]="Internet-exposed service review"   [06]="Subdomain takeover / cloud"
    [07]="Vulnerability detection"           [08]="Consolidated reporting"
    [09]="Final XLSX report (AI)"
  )
else
  BANNER=$(cat <<'B'
  ___ _  _ _____ ___ ___ _  _   _   _    ___ ___ ___ ___  _  _
 |_ _| \| |_   _| __| _ \ \| | /_\ | |  | _ \ __/ __/ _ \| \| |
  | || .` | | | | _||   / .` |/ _ \| |__|   / _| (_| (_) | .` |
 |___|_|\_| |_| |___|_|_\_|\_/_/ \_\____|_|_\___\___\___/|_|\_|
              internal network recon kit  (recon-only)
B
)
  MENU_TITLE='CEDZO · internal network recon kit'
  PHASE_ORDER=(01 02 03 04 05 06 07 08 09)
  declare -A MODULE=(
    [01]=01-prep.sh        [02]=02-portscan.sh   [03]=03-enum-smb-ad.sh
    [04]=04-enum-web.sh    [05]=05-enum-db.sh    [06]=06-ad-recon.sh
    [07]=07-vuln-scan.sh   [08]=08-report.sh     [09]=09-xlsx-report.sh
  )
  declare -A PHASE_DESC=(
    [01]="Preflight & live-host list"   [02]="Port & service scan"
    [03]="SMB / AD enumeration"         [04]="Web enumeration"
    [05]="Database enumeration"         [06]="AD recon (roasting / BloodHound)"
    [07]="Vulnerability detection"      [08]="Consolidated reporting"
    [09]="Final XLSX report (AI)"
  )
fi

printf '%s%s%s\n' "$C_CYN" "$BANNER" "$C_RST"

# ---- Config sanity (advisory; never hard-fails) --------------------------
validate_config

# ---- Project selection ----------------------------------------------------
# The output is namespaced by a PROJECT name. Re-using a name RESUMES that
# project (completed phases AND sub-tasks are skipped); a brand-new name starts
# a fresh scan. Provide it non-interactively via the PROJECT env var, else prompt.
PROJECT="${PROJECT:-}"
if [[ -z "$PROJECT" ]]; then
  read -rp "$(printf ' %sproject name%s (re-use to resume, new name to start fresh) ▸ ' "$C_CYN" "$C_RST")" PROJECT
fi
# Sanitise to a filesystem-safe slug: spaces -> '_', keep [A-Za-z0-9._-] only.
PROJECT=$(printf '%s' "$PROJECT" | tr ' ' '_' | tr -cd 'A-Za-z0-9._-')
[[ -n "$PROJECT" ]] || { err "A project name is required. Exiting."; exit 1; }
PROJECT_DIR="$OUTPUT_BASE/$PROJECT"

# ---- Scope (per project) --------------------------------------------------
# Each project keeps its OWN scope at <project>/scope.txt, shared by that
# project's internal and external runs. First use seeds it from the root scope
# (config's SCOPE_FILE); after that the project copy is authoritative, so editing
# it never disturbs another engagement.
PROJ_SCOPE="$PROJECT_DIR/scope.txt"
if [[ -s "$PROJ_SCOPE" ]]; then
  SCOPE_FILE="$PROJ_SCOPE"
  ok "Using project scope: $PROJ_SCOPE"
elif [[ -s "$SCOPE_FILE" ]]; then
  mkdir -p "$PROJECT_DIR"
  cp "$SCOPE_FILE" "$PROJ_SCOPE"
  SCOPE_FILE="$PROJ_SCOPE"
  ok "Seeded project scope from root scope.txt -> $PROJ_SCOPE (edit it for project-specific targets)"
fi
# Absolutise so phases that cd elsewhere still resolve it.
_sdir="$(cd "$(dirname "$SCOPE_FILE")" 2>/dev/null && pwd || true)"
[[ -n "$_sdir" ]] && SCOPE_FILE="$_sdir/$(basename "$SCOPE_FILE")"
export SCOPE_FILE

# ---- Authorisation / scope gate ------------------------------------------
require_scope
N=$(clean_scope | wc -l)
if [[ "$KIT_MODE" == "external" ]]; then
  warn "Scope: $N entries from '$SCOPE_FILE'. This runs ACTIVE recon against INTERNET-FACING assets."
  warn "Only proceed if you have WRITTEN authorisation covering every target IP/range/domain."
  warn "External scanning crosses third-party networks — confirm your rules of engagement (rate limits, hours, source IP)."
else
  warn "Scope: $N entries from '$SCOPE_FILE'. This runs ACTIVE recon scanning against them."
  warn "Only proceed if you have WRITTEN authorisation covering every target."
fi
read -rp "Type the word AUTHORISED to continue: " a
[[ "$a" == "AUTHORISED" ]] || { err "Not confirmed. Exiting."; exit 1; }

# ---- Run directory (per project + mode — re-runs resume from the first
# unfinished phase, and within a phase from the first unfinished sub-task). A
# re-run of the SAME project name picks up where it left off. Force a phase to
# re-run by naming it explicitly (./run.sh <mode> 04) or deleting its marker; a
# NEW project name gets a fresh directory and runs from the beginning. Internal
# and external live in separate sub-dirs so their markers never clash.
export RUN="$PROJECT_DIR/$KIT_MODE"
if [[ -d "$RUN" ]] && compgen -G "$RUN/.done-*" >/dev/null 2>&1; then
  ok "Resuming project '$PROJECT' ($KIT_MODE) — completed phases/sub-tasks will be skipped."
else
  ok "Starting new scan — project '$PROJECT' ($KIT_MODE)."
fi
mkdir -p "$RUN"
# Resolve RUN to an ABSOLUTE path. Phases that `cd` elsewhere (e.g. the phase-09
# archive task does `cd "$RUN"`) must still be able to reference "$RUN", which a
# relative path would break.
RUN="$(cd "$RUN" && pwd)"; export RUN
cp "$SCOPE_FILE" "$RUN/scope.txt"
ok "Output directory: $RUN"
exec > >(tee -a "$RUN/run.log") 2>&1   # full transcript

# Menu styling (bold tracks whether colours are enabled; BAR = left accent).
C_BLD=''; [[ -n "$C_CYN" ]] && C_BLD=$'\e[1m'
BAR="${C_CYN}┃${C_RST}"

# Run one phase (all its sub-tasks). Exports PHASE_ID so the sub-task framework
# can drop per-task resume markers. fresh=1 (default) clears any prior sub-task
# markers for this phase so it fully re-runs; fresh=0 keeps them so a phase that
# died partway resumes at its first unfinished sub-task.
run_phase() {
  local p="$1" fresh="${2:-1}" script="${MODULE[$1]:-}"
  [[ -n "$script" ]] || { warn "Unknown phase '$p' — skipping."; return 0; }
  if (( fresh )); then rm -f "$RUN/.tasks/$p-"*.done 2>/dev/null || true; fi
  phase "PHASE $p — $script"
  if PHASE_ID="$p" RUN="$RUN" bash "./$script"; then
    touch "$RUN/.done-$p"
  else
    warn "Phase $p exited non-zero — not marking complete; it will retry (resuming sub-tasks) next run."
  fi
}

# Run a list of phases. In resume mode (explicit=false) phases with a .done
# marker are skipped and partial phases RESUME their sub-tasks (fresh=0);
# explicit selection always re-runs the whole phase cleanly (fresh=1).
run_phases() {
  local explicit="$1"; shift
  local p fresh=0
  [[ "$explicit" == "true" ]] && fresh=1
  for p in "$@"; do
    [[ -n "${MODULE[$p]:-}" ]] || { warn "Unknown phase '$p' — skipping."; continue; }
    if [[ "$explicit" == "false" && -f "$RUN/.done-$p" ]]; then
      ok "PHASE $p — ${MODULE[$p]} already complete — skipping (rm $RUN/.done-$p to redo)."
      continue
    fi
    run_phase "$p" "$fresh"
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
  if [[ "$KIT_MODE" == "external" ]]; then
    echo "  - $RUN/REPORT.md                     (consolidated external recon summary, Markdown)"
    echo "  - $RUN/nmap_report.html              (infrastructure intel + risk scores)"
    echo "  - $RUN/web_report.html               (web vulnerabilities, severity-ranked)"
    echo "  - $RUN/risky_services.txt            (services that should NOT face the Internet)"
    echo "  - $RUN/05-exposure/*.txt             (exposed RDP/SSH/DB/appliances)"
    echo "  - $RUN/06-takeover/takeover.txt      (subdomain-takeover candidates)"
    echo "  - $RUN/07-vuln/nuclei_cve.txt        (high-impact external CVEs)"
    echo "  - $RUN/02-osint/subdomains.txt       (discovered subdomains)"
  else
    echo "  - $RUN/REPORT.md                     (consolidated recon summary, Markdown)"
    echo "  - $RUN/nmap_report.html              (infrastructure intel + risk scores)"
    echo "  - $RUN/web_report.html               (web vulnerabilities, severity-ranked)"
    echo "  - $RUN/07-vuln/*_summary.txt         (EternalBlue/Zerologon/etc. detections)"
    echo "  - $RUN/03-smb-ad/shares*             (readable shares, null sessions)"
    echo "  - $RUN/04-web/nuclei.txt             (web findings)"
    echo "  - $RUN/06-ad-recon/*hashes.txt       (crack OFFLINE w/ hashcat)"
    echo "  - $RUN/05-db/db_nse.nmap             (empty-password DBs)"
  fi
  if [[ "${AI_PROVIDER:-none}" != "none" ]]; then
    echo "  - $RUN/pentest_vulnerability_report.xlsx  (AI client report: findings + attack chains)"
    echo "  - $RUN/ai/executive_summary.md       (AI executive summary; also in REPORT.md)"
    echo "  - $RUN/ai/0*-*.md                    (AI per-phase triage analysis)"
  fi
  [[ -f "$RUN/cedzo_results.zip" ]] && echo "  - $RUN/cedzo_results.zip             (full run archive)"
  [[ -f "$RUN/exdzo_results.zip" ]] && echo "  - $RUN/exdzo_results.zip             (full run archive)"
}

# ---- Interactive sub-task menu: phase 01..09 -> sub-task -> run -----------
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
    printf ' %s  %s%s%s%s\n' "$BAR" "$C_BLD" "$C_CYN" "$MENU_TITLE" "$C_RST"
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
