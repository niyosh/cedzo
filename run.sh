#!/usr/bin/env bash
# ==========================================================================
# run.sh  -  Orchestrator. Runs the recon phases in order against your scope.
#
#   ./run.sh                 # full recon chain (AD recon needs read-only creds)
#   ./run.sh 00 02 04        # run only selected phases
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

# ---- Run directory --------------------------------------------------------
export RUN="$OUTPUT_BASE/run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN"
cp "$SCOPE_FILE" "$RUN/scope.txt"
ok "Output directory: $RUN"
exec > >(tee -a "$RUN/run.log") 2>&1   # full transcript

PHASES=("$@")
[[ ${#PHASES[@]} -eq 0 ]] && PHASES=(00 02 03 04 05 06 07 08)

declare -A MODULE=(
  [00]=00-prep.sh        [02]=02-portscan.sh   [03]=03-enum-smb-ad.sh
  [04]=04-enum-web.sh    [05]=05-enum-db.sh    [06]=06-ad-recon.sh
  [07]=07-vuln-scan.sh   [08]=08-report.sh
)

START=$(date +%s)
for p in "${PHASES[@]}"; do
  script="${MODULE[$p]:-}"
  [[ -n "$script" ]] || { warn "Unknown phase '$p' — skipping."; continue; }
  phase "PHASE $p — $script"
  RUN="$RUN" bash "./$script" || warn "Phase $p exited non-zero (continuing)."
done

DUR=$(( $(date +%s) - START ))
phase "DONE in $((DUR/60))m $((DUR%60))s"
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
