#!/usr/bin/env bash
# ==========================================================================
# 08-report.sh  -  Consolidate every module's output into a single
#                  enterprise-ready Markdown report: $RUN/REPORT.md
# Read-only over the run directory; produces no network traffic.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
REPORT="$RUN/REPORT.md"

phase "Consolidated Reporting"

# Helpers -------------------------------------------------------------------
count() { [[ -s "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }   # lines in file or 0
emit()  { printf '%s\n' "$*" >> "$REPORT"; }
section_file() {                       # heading, file, fenced? -> append if non-empty
  local title="$1" file="$2" fence="${3:-yes}"
  [[ -s "$file" ]] || return 0
  emit ""; emit "### $title"; emit ""
  if [[ "$fence" == "yes" ]]; then emit '```'; cat "$file" >> "$REPORT"; emit '```'
  else cat "$file" >> "$REPORT"; fi
}

# Header --------------------------------------------------------------------
: > "$REPORT"
emit "# Internal Network Recon Report"
emit ""
emit "- **Generated:** $(date '+%Y-%m-%d %H:%M:%S %Z')"
emit "- **Run directory:** \`$RUN\`"
emit "- **Scope file:** \`$SCOPE_FILE\` ($(count "$RUN/scope.txt") entries)"
emit "- **Engagement type:** Recon-only (no exploitation, spraying, brute force, or disruptive actions)"
emit ""

# Executive summary table ---------------------------------------------------
emit "## Asset Summary"
emit ""
emit "| Metric | Count |"
emit "|--------|-------|"
emit "| Hosts in scope (treated live) | $(count "$RUN/live_hosts.txt") |"
emit "| Hosts with open TCP ports | $(count "$RUN/02-portscan/host_ports.txt") |"
emit "| SMB hosts | $(count "$RUN/hosts_smb.txt") |"
emit "| Domain Controllers | $(count "$RUN/hosts_dc.txt") |"
emit "| Web services | $(count "$RUN/web_urls.txt") |"
emit "| Database hosts | $(count "$RUN/hosts_db.txt") |"
emit "| RDP hosts | $(count "$RUN/hosts_rdp.txt") |"
emit "| WinRM hosts | $(count "$RUN/hosts_winrm.txt") |"
emit "| Harvested domain users | $(count "$RUN/domain_users.txt") |"
emit ""

# Per-role host lists -------------------------------------------------------
emit "## Hosts by Role"
for role in smb dc web db rdp winrm; do
  f="$RUN/hosts_$role.txt"
  [[ -s "$f" ]] || continue
  emit ""; emit "### ${role^^} ($(count "$f"))"; emit '```'
  cat "$f" >> "$REPORT"; emit '```'
done
emit ""

# Open ports map ------------------------------------------------------------
section_file "Open Ports (host → ports)" "$RUN/02-portscan/host_ports.txt"

# Web findings --------------------------------------------------------------
emit ""; emit "## Web"
section_file "httpx fingerprint" "$RUN/04-web/httpx.txt"
if [[ -s "$RUN/04-web/nuclei.txt" ]]; then
  emit ""; emit "### nuclei findings ($(count "$RUN/04-web/nuclei.txt"))"; emit '```'
  cat "$RUN/04-web/nuclei.txt" >> "$REPORT"; emit '```'
fi
[[ -d "$RUN/04-web/screens" ]] && { emit ""; emit "Screenshots: \`$RUN/04-web/screens/\`"; }

# SMB / AD enumeration ------------------------------------------------------
emit ""; emit "## SMB / Active Directory"
section_file "Enumerated users" "$RUN/03-smb-ad/users.txt"
[[ -d "$RUN/03-smb-ad" ]] && {
  shares=$(ls "$RUN/03-smb-ad"/shares* 2>/dev/null | head -1 || true)
  [[ -n "$shares" ]] && section_file "Shares" "$shares"
}

# Database enumeration ------------------------------------------------------
emit ""; emit "## Databases"
section_file "DB NSE results" "$RUN/05-db/db_nse.nmap"

# Vulnerability DETECTIONS (non-exploitative) -------------------------------
emit ""; emit "## Vulnerability Detections (non-exploitative — validate manually)"
section_file "SMB vulnerability checks" "$RUN/07-vuln/smb_vuln_summary.txt"
section_file "netexec vulnerability checks" "$RUN/07-vuln/nxc_vuln_summary.txt"
section_file "SNMP default-community hits" "$RUN/07-vuln/snmp_hits.txt"
[[ -s "$RUN/07-vuln/tls_audit.txt" ]] && { emit ""; emit "TLS audit detail: \`$RUN/07-vuln/tls_audit.txt\`"; }

# AD recon collection -------------------------------------------------------
emit ""; emit "## AD Recon Collection (crack OFFLINE, out of band)"
kr=$(count "$RUN/06-ad-recon/kerberoast_hashes.txt")
ar=$(count "$RUN/06-ad-recon/asrep_hashes.txt")
emit ""
emit "- Kerberoast hashes collected: **$kr** (\`hashcat -m 13100\`)"
emit "- AS-REP hashes collected: **$ar** (\`hashcat -m 18200\`)"
[[ -d "$RUN/06-ad-recon/bloodhound" ]] && emit "- BloodHound data: \`$RUN/06-ad-recon/bloodhound/\` (import into BloodHound GUI)"
emit ""

emit "---"
emit "_Recon-only engagement. All findings are observations or detections;"
emit "no exploitation was performed. Validate every detection within your RoE_"
emit "_before any follow-up action._"

ok "Consolidated report -> $REPORT"
have glow && glow "$REPORT" 2>/dev/null || true

# ---- HTML reports (infrastructure + web vuln) -----------------------------
# Render rich, shareable HTML alongside the Markdown summary. The Python
# reporters walk the run dir for *.nmap and nuclei *.txt output.
if have python3; then
  phase "HTML Reporting"
  python3 reporting/nmap2html.py   -i "$RUN" -o "$RUN/nmap_report.html" 2>/dev/null \
    && ok "Infrastructure report -> $RUN/nmap_report.html" \
    || warn "nmap2html skipped (no parseable .nmap output?)"
  python3 reporting/nuclei2html.py -i "$RUN" -o "$RUN/web_report.html" 2>/dev/null \
    && ok "Web vulnerability report -> $RUN/web_report.html" \
    || warn "nuclei2html skipped (no nuclei output?)"
else
  warn "python3 not found — skipping HTML reports (Markdown REPORT.md still generated)."
fi
