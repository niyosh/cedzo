#!/usr/bin/env bash
# ==========================================================================
# 09-xlsx-report.sh  -  Final client deliverable.
#
# Archives the whole run, hands the consolidated results to Claude, and renders
# the response into the house vulnerability-report spreadsheet:
#     $RUN/pentest_vulnerability_report.xlsx
#       · Sheet "Vulnerabilities"        — severity-ranked finding register
#       · Sheet "Attack Paths & Chains"  — realistic attacker chains
#
# This phase is AI-driven: with AI off it archives the run and skips the
# spreadsheet (the prose lives in REPORT.md). Enable with AI_PROVIDER=anthropic.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
XLSX="$RUN/pentest_vulnerability_report.xlsx"

phase "Final XLSX Vulnerability Report"

# ---- Sub-task: archive the full run (operator/client record) --------------
# The model is sent a bounded TEXT digest (binary zips aren't model-readable);
# this archive is the human-facing "all the raw results" bundle.
t_zip() {
  local zip="$RUN/cedzo_results.zip"
  log "Archiving run results"
  if have zip; then
    ( cd "$RUN" && zip -rq cedzo_results.zip . -x 'cedzo_results.zip' 'ai/log/*' ) || true
    [[ -s "$zip" ]] && ok "Results archive -> $zip" || warn "zip produced no archive."
  elif have tar; then
    tar -czf "$RUN/cedzo_results.tar.gz" -C "$RUN" --exclude='./ai/log' . 2>/dev/null || true
    [[ -s "$RUN/cedzo_results.tar.gz" ]] && ok "Results archive -> $RUN/cedzo_results.tar.gz" \
      || warn "tar produced no archive."
  else
    warn "Neither zip nor tar found — skipping results archive."
  fi
}

# ---- Sub-task: AI authors the findings register ---------------------------
t_ai_findings() {
  [[ -s "$RUN/REPORT.md" ]] || warn "REPORT.md not found — run phase 08 first for the richest input."
  ai_xlsx_report
}

# ---- Sub-task: render the .xlsx from the AI JSON --------------------------
t_render() {
  local j="$RUN/ai/xlsx-report.json"
  if [[ ! -s "$j" ]]; then
    warn "No AI findings JSON yet ($j) — XLSX not rendered."
    if [[ -s "$RUN/ai/offline/xlsx-report.prompt.md" ]]; then
      log  "Manual path: paste $RUN/ai/offline/xlsx-report.prompt.md into an AI,"
      log  "  save its JSON reply to $j, then re-run:  ./run.sh 09"
    else
      log  "Configure a provider (AI_PROVIDER=anthropic|openai|gemini|ollama) and re-run."
    fi
    return 0
  fi
  have python3 || { warn "python3 missing — cannot render XLSX."; return 0; }
  # Best-effort openpyxl bootstrap (apt python3-openpyxl, or pip).
  if ! python3 -c 'import openpyxl' 2>/dev/null; then
    python3 -m pip install --quiet openpyxl 2>/dev/null \
      || python3 -m pip install --quiet --break-system-packages openpyxl 2>/dev/null || true
  fi
  python3 -c 'import openpyxl' 2>/dev/null \
    || { warn "openpyxl unavailable — 'pip install openpyxl' (or apt install python3-openpyxl). Skipping render."; return 0; }
  if python3 reporting/xlsx_report.py --json "$j" -o "$XLSX"; then
    ok "Client report -> $XLSX"
  else
    warn "XLSX render failed (see above)."
  fi
}

# Order matters: author (or write the offline pack) BEFORE zipping, so the zip
# bundles the manual prompt pack too; render last.
task ai_findings "AI: author register + chains (or offline pack)" t_ai_findings
task zip         "Archive full run results (zip/tar)"             t_zip
task render      "Render client .xlsx from AI findings"           t_render
run_tasks

ok "Final report module complete."
if [[ -s "$XLSX" ]]; then
  ok "Deliverable: $XLSX"
elif [[ -s "$RUN/ai/offline/xlsx-report.prompt.md" ]]; then
  warn "No AI configured — manual report path:"
  log  "  1. Open  $RUN/ai/offline/xlsx-report.prompt.md  (also inside the results zip)"
  log  "  2. Paste it into ChatGPT / Claude / Gemini / a local model"
  log  "  3. Save the JSON reply to  $RUN/ai/xlsx-report.json"
  log  "  4. Run  ./run.sh 09   to render $XLSX"
fi
