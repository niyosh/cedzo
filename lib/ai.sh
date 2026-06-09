#!/usr/bin/env bash
# ==========================================================================
# lib/ai.sh  -  Claude-backed analysis layer (sourced by lib/common.sh).
#
# Design contract (read before touching this file):
#   * The AI is a TRIAGE/CORRELATION layer that sits BETWEEN phases. It reads
#     a phase's evidence and writes structured JSON + Markdown to $RUN/ai/.
#   * Tools remain ground truth. The model never scans, never exploits, and
#     NOTHING it returns is turned into a shell command. The one place its
#     output influences a tool (nuclei `-tags`) is sanitised to [a-z0-9_-]
#     and runs as an ADDITIVE pass, so it can never reduce coverage.
#   * Failure is always non-fatal: every entry point returns 0/empty on any
#     error so a phase never aborts because the API was down.
#   * Privacy: all evidence passes through _ai_redact before it leaves the
#     box; raw hash files and the secrets report are never sent.
#
# Transport is raw HTTPS via curl + jq (this is a shell project), targeting
# POST /v1/messages with structured outputs (output_config.format) so every
# response is schema-valid JSON we can parse deterministically.
# ==========================================================================

# ---- Availability gate ----------------------------------------------------
ai_available() {
  [[ "${AI_PROVIDER:-none}" == "anthropic" ]] || return 1
  [[ -n "${ANTHROPIC_API_KEY:-}" ]] || { warn "AI: AI_PROVIDER=anthropic but ANTHROPIC_API_KEY is empty — skipping."; return 1; }
  have curl || { warn "AI: curl not found — skipping AI analysis."; return 1; }
  have jq   || { warn "AI: jq not found — skipping AI analysis."; return 1; }
  return 0
}

# ---- Redaction ------------------------------------------------------------
# Mask the obvious secrets before any evidence is sent. Deliberately blunt —
# better to over-mask than to leak a client credential to a third party.
_ai_redact() {
  if [[ "${AI_REDACT_SECRETS:-true}" != "true" ]]; then cat; return 0; fi
  sed -E \
    -e 's/((pass(word)?|pwd|cpassword|secret|api[_-]?key|token)[[:space:]]*[:=][[:space:]]*)[^[:space:]"]+/\1[REDACTED]/Ig' \
    -e 's/\$(krb5asrep|krb5tgs|NTLMv2|sntp-ms)\$[^[:space:]]+/[REDACTED-HASH]/Ig' \
    -e 's/\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b/[REDACTED-NTLM]/g' \
    -e 's/-----BEGIN ([A-Z ]+)PRIVATE KEY-----/[REDACTED-PRIVATE-KEY]/g'
}

# ---- Evidence collection --------------------------------------------------
# _ai_cat <label> <file>  ->  appends a bounded, labelled, redacted block.
_ai_cat() {
  local label="$1" f="$2"
  [[ -s "$f" ]] || return 0
  printf '\n===== %s  [%s] =====\n' "$label" "$f"
  head -c "${AI_PER_FILE_CHARS:-24000}" "$f" | _ai_redact
  printf '\n'
}

# _ai_cat_glob <label> <glob...>  ->  bounded block per matching file.
_ai_cat_glob() {
  local label="$1"; shift
  local f
  for f in "$@"; do [[ -s "$f" ]] && _ai_cat "$label" "$f"; done
}

_ai_bound() { head -c "${AI_MAX_INPUT_CHARS:-160000}"; }

# Line count of a file, or 0 (self-contained — `count` only exists in phase 08).
_ai_count() { [[ -s "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

# ---- JSON schemas ---------------------------------------------------------
# Structured-output schemas. Kept jq-simple (no minItems/recursion) so the
# API accepts them. cat-from-heredoc is set -e safe.
_schema_generic() {
cat <<'JSON'
{
  "type": "object", "additionalProperties": false,
  "properties": {
    "summary": { "type": "string" },
    "key_findings": {
      "type": "array",
      "items": {
        "type": "object", "additionalProperties": false,
        "properties": {
          "title":     { "type": "string" },
          "severity":  { "type": "string", "enum": ["INFO","LOW","MEDIUM","HIGH","CRITICAL"] },
          "rationale": { "type": "string" },
          "evidence":  { "type": "string" }
        },
        "required": ["title","severity","rationale","evidence"]
      }
    },
    "next_steps": { "type": "array", "items": { "type": "string" } }
  },
  "required": ["summary","key_findings","next_steps"]
}
JSON
}

_schema_web() {
cat <<'JSON'
{
  "type": "object", "additionalProperties": false,
  "properties": {
    "summary": { "type": "string" },
    "key_findings": {
      "type": "array",
      "items": {
        "type": "object", "additionalProperties": false,
        "properties": {
          "title":     { "type": "string" },
          "severity":  { "type": "string", "enum": ["INFO","LOW","MEDIUM","HIGH","CRITICAL"] },
          "rationale": { "type": "string" },
          "evidence":  { "type": "string" }
        },
        "required": ["title","severity","rationale","evidence"]
      }
    },
    "nuclei_tags":   { "type": "array", "items": { "type": "string" } },
    "priority_urls": { "type": "array", "items": { "type": "string" } },
    "next_steps":    { "type": "array", "items": { "type": "string" } }
  },
  "required": ["summary","key_findings","nuclei_tags","priority_urls","next_steps"]
}
JSON
}

_schema_exec() {
cat <<'JSON'
{
  "type": "object", "additionalProperties": false,
  "properties": {
    "executive_summary": { "type": "string" },
    "overall_risk": { "type": "string", "enum": ["INFO","LOW","MEDIUM","HIGH","CRITICAL"] },
    "top_risks": {
      "type": "array",
      "items": {
        "type": "object", "additionalProperties": false,
        "properties": {
          "rank":            { "type": "integer" },
          "severity":        { "type": "string", "enum": ["INFO","LOW","MEDIUM","HIGH","CRITICAL"] },
          "finding":         { "type": "string" },
          "business_impact": { "type": "string" },
          "remediation":     { "type": "string" }
        },
        "required": ["rank","severity","finding","business_impact","remediation"]
      }
    },
    "attack_path_narrative": { "type": "string" },
    "recommended_actions":   { "type": "array", "items": { "type": "string" } }
  },
  "required": ["executive_summary","overall_risk","top_risks","attack_path_narrative","recommended_actions"]
}
JSON
}

# ---- HTTP transport -------------------------------------------------------
# _ai_post <name> <request-json>  ->  prints concatenated assistant text.
# Retries rate-limit / overload; logs request+response under $RUN/ai/log.
_ai_post() {
  local name="$1" req="$2" attempt resp errtype
  local logd="$RUN/ai/log"; mkdir -p "$logd"
  for attempt in 1 2 3; do
    resp=$(printf '%s' "$req" | curl -sS --max-time "${AI_TIMEOUT:-180}" \
        -H "content-type: application/json" \
        -H "x-api-key: $ANTHROPIC_API_KEY" \
        -H "anthropic-version: 2023-06-01" \
        "$AI_BASE_URL/v1/messages" --data-binary @- 2>/dev/null) || resp=""
    printf '%s' "$resp" > "$logd/$name.resp.json"
    if [[ -z "$resp" ]]; then warn "AI[$name]: empty/failed response (attempt $attempt/3)"; sleep 3; continue; fi
    if printf '%s' "$resp" | jq -e 'has("error")' >/dev/null 2>&1; then
      errtype=$(printf '%s' "$resp" | jq -r '.error.type // "error"')
      case "$errtype" in
        rate_limit_error|overloaded_error|api_error)
          warn "AI[$name]: $errtype (retry $attempt/3)"; sleep 5; continue ;;
        *)
          err "AI[$name]: $(printf '%s' "$resp" | jq -r '.error.type+": "+.error.message')"; return 1 ;;
      esac
    fi
    printf '%s' "$resp" | jq -r '[.content[]? | select(.type=="text") | .text] | join("")'
    return 0
  done
  warn "AI[$name]: gave up after 3 attempts."; return 1
}

# _ai_json <name> <system> <user-evidence> <schema-json>
# Writes validated JSON to $RUN/ai/<name>.json. Returns 1 on any failure.
_ai_json() {
  local name="$1" system="$2" user="$3" schema="$4"
  local dir="$RUN/ai" logd="$RUN/ai/log"; mkdir -p "$dir" "$logd"
  local req text
  req=$(jq -n \
        --arg m "$AI_MODEL" --argjson mt "${AI_MAX_TOKENS:-8000}" --arg eff "${AI_EFFORT:-high}" \
        --arg sys "$system" --arg usr "$user" --argjson schema "$schema" \
        '{ model:$m, max_tokens:$mt,
           thinking:{type:"adaptive"},
           system:$sys,
           output_config:{ effort:$eff, format:{ type:"json_schema", schema:$schema } },
           messages:[ {role:"user", content:$usr} ] }') \
    || { warn "AI[$name]: failed to build request JSON"; return 1; }
  printf '%s' "$req" > "$logd/$name.req.json"

  text=$(_ai_post "$name" "$req") || return 1
  if printf '%s' "$text" | jq -e . >/dev/null 2>&1; then
    printf '%s' "$text" | jq . > "$dir/$name.json"
    return 0
  fi
  warn "AI[$name]: response was not valid JSON (raw -> $dir/$name.raw.txt)"
  printf '%s' "$text" > "$dir/$name.raw.txt"
  return 1
}

# ---- Markdown rendering ----------------------------------------------------
_ai_banner() {
  printf '> ⚠️ **AI-generated** (model: `%s`). Triage guidance only — not a CVSS score and not ground truth. Validate every item against the linked evidence before acting.\n' "$AI_MODEL"
}

_ai_render_generic() {   # <json> <out.md> <title>
  local json="$1" out="$2" title="$3"
  { echo "# $title"; echo; _ai_banner; echo
    echo "## Summary"; echo; jq -r '.summary' "$json"; echo
    echo "## Key findings (AI-ranked)"; echo
    jq -r '.key_findings[]? | "- **\(.severity)** — \(.title)\n  - why: \(.rationale)\n  - evidence: \(.evidence)"' "$json"
    echo; echo "## Suggested next steps"; echo
    jq -r '.next_steps[]? | "- \(.)"' "$json"
  } > "$out"
}

# ---- The phase runner -----------------------------------------------------
# _ai_phase <name> <title> <schema-json> <system> <evidence>
#   * skips cleanly when AI is off or there is no evidence
#   * writes $RUN/ai/<name>.json and $RUN/ai/<name>.md
#   * returns 0 on success (so callers can add phase-specific extras)
_ai_phase() {
  local name="$1" title="$2" schema="$3" system="$4" evidence="$5"
  ai_available || return 1
  if [[ -z "${evidence//[[:space:]]/}" ]]; then
    log "AI[$name]: no evidence collected — skipping analysis."; return 1
  fi
  log "AI[$name]: analysing $(printf '%s' "$evidence" | wc -c) bytes of evidence with $AI_MODEL ..."
  _ai_json "$name" "$system" "$evidence" "$schema" || return 1
  _ai_render_generic "$RUN/ai/$name.json" "$RUN/ai/$name.md" "$title"
  ok "AI[$name]: analysis -> $RUN/ai/$name.md"
  return 0
}

# Shared system-prompt preamble for the recon-triage persona.
_AI_PERSONA='You are a senior penetration tester triaging the output of an
internal-network RECON tool (discovery/enumeration only — no exploitation was
performed). You are given raw tool output for one phase. Analyse it and return
ONLY the requested JSON. Be concrete and reference the actual hosts, ports,
services, shares, or findings present in the evidence — never invent hosts or
results that are not in the data. Rank by realistic attacker value on an
internal engagement. Sensitive values may appear as [REDACTED]; reason about
their presence without needing the secret itself.'

# ==========================================================================
# Per-phase bridges. Each is registered as a sub-task in its phase file.
# ==========================================================================

# ---- Phase 02: port/service triage ---------------------------------------
ai_bridge_02() {
  ai_available || { log "AI off — skipping phase-02 analysis."; return 0; }
  local O="$RUN/02-portscan"
  local ev; ev=$( {
    _ai_cat "Host -> open ports" "$O/host_ports.txt"
    _ai_cat_glob "Service/version scan" "$O"/hosts/*/service.nmap
    _ai_cat "Role: SMB"  "$RUN/hosts_smb.txt"
    _ai_cat "Role: DC"   "$RUN/hosts_dc.txt"
    _ai_cat "Role: web"  "$RUN/hosts_web.txt"
    _ai_cat "Role: DB"   "$RUN/hosts_db.txt"
    _ai_cat "Web URLs"   "$RUN/web_urls.txt"
  } | _ai_bound )
  _ai_phase 02-portscan "Phase 02 — Service Triage" "$(_schema_generic)" \
    "$_AI_PERSONA Focus: which hosts/services are highest-value, any odd or
mis-fingerprinted ports worth a second look, and what later phases should
prioritise." "$ev" || return 0
  # Targeting hint for later phases (advisory; not auto-consumed).
  jq -r '.key_findings[]? | select(.severity=="HIGH" or .severity=="CRITICAL") | .evidence' \
    "$RUN/ai/02-portscan.json" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | sort -u > "$RUN/ai/priority_hosts.txt" 2>/dev/null || true
}

# ---- Phase 03: SMB / AD enumeration triage --------------------------------
ai_bridge_03() {
  ai_available || { log "AI off — skipping phase-03 analysis."; return 0; }
  local O="$RUN/03-smb-ad"
  local ev; ev=$( {
    _ai_cat_glob "SMB shares" "$O"/shares*
    _ai_cat "Enumerated users" "$O/users.txt"
    _ai_cat "RID brute" "$O/rid_brute.txt"
    _ai_cat "GPP creds (SYSVOL)" "$O/gpp_creds.txt"
    _ai_cat_glob "Anonymous LDAP" "$O"/ldap_anon_*.txt
    _ai_cat_glob "DNS AXFR" "$O"/axfr_*.txt
    _ai_cat "NFS exports" "$O/nfs_exports.txt"
    _ai_cat "NFS listings" "$O/nfs_listing.txt"
    _ai_cat "Harvested domain users" "$RUN/domain_users.txt"
  } | _ai_bound )
  _ai_phase 03-smb-ad "Phase 03 — SMB / AD Triage" "$(_schema_generic)" \
    "$_AI_PERSONA Focus: interesting share names worth manual review (backups,
finance, IT, scripts), null/anonymous access, AXFR/anon-LDAP exposure, and any
credential leakage. Flag share names that commonly hold secrets." "$ev" || return 0
}

# ---- Phase 04: web fingerprint -> nuclei targeting ------------------------
# Runs BEFORE the nuclei sub-task so its tag suggestions can drive an extra,
# additive nuclei pass. Sanitisation of tags happens at consumption time.
ai_bridge_04() {
  ai_available || { log "AI off — skipping phase-04 analysis."; return 0; }
  local O="$RUN/04-web"
  local ev; ev=$( {
    _ai_cat "httpx fingerprint" "$O/httpx.txt"
    _ai_cat "whatweb" "$O/whatweb.txt"
    _ai_cat "favicon hashes" "$O/favicon.txt"
    _ai_cat "exposed paths" "$O/exposures.txt"
    _ai_cat "NTLM endpoints" "$O/ntlmrecon.csv"
    _ai_cat "shortscan" "$O/shortscan.txt"
    _ai_cat "discovered endpoints" "$O/nuclei_targets.txt"
    _ai_cat "live URLs" "$O/live_urls.txt"
  } | _ai_bound )
  _ai_phase 04-web "Phase 04 — Web Triage" "$(_schema_web)" \
    "$_AI_PERSONA Focus: map the detected tech stack to the most relevant nuclei
template TAGS (e.g. tomcat, jenkins, gitlab, wordpress, springboot, iis,
exchange, fortinet, citrix) so a targeted scan can run. Return tags as lowercase
nuclei tag tokens. Also list the highest-value URLs to review by hand." "$ev" || return 0
  # Emit sanitised tag list for the (additive) AI-targeted nuclei pass.
  jq -r '.nuclei_tags[]?' "$RUN/ai/04-web.json" 2>/dev/null \
    | tr 'A-Z' 'a-z' | grep -oE '[a-z0-9_-]+' | sort -u > "$O/ai_nuclei_tags.txt" 2>/dev/null || true
  [[ -s "$O/ai_nuclei_tags.txt" ]] && ok "AI[04-web]: nuclei tags -> $O/ai_nuclei_tags.txt ($(wc -l <"$O/ai_nuclei_tags.txt"))"
  # Append the web-specific fields to the rendered markdown.
  {
    echo; echo "## AI-recommended nuclei tags"; echo
    jq -r '.nuclei_tags[]? | "- `\(.)`"' "$RUN/ai/04-web.json" 2>/dev/null
    echo; echo "## Priority URLs to review"; echo
    jq -r '.priority_urls[]? | "- \(.)"' "$RUN/ai/04-web.json" 2>/dev/null
  } >> "$RUN/ai/04-web.md" 2>/dev/null || true
}

# ---- Phase 05: database triage --------------------------------------------
ai_bridge_05() {
  ai_available || { log "AI off — skipping phase-05 analysis."; return 0; }
  local O="$RUN/05-db"
  local ev; ev=$( {
    _ai_cat "DB NSE" "$O/db_nse.nmap"
    _ai_cat "DB phase log" "$O/db.log"
    _ai_cat "DB hosts" "$RUN/hosts_db.txt"
  } | _ai_bound )
  _ai_phase 05-db "Phase 05 — Database Triage" "$(_schema_generic)" \
    "$_AI_PERSONA Focus: empty/weak-password databases, exposed versions with
known CVE classes, and which DB hosts to prioritise. Map versions to likely
CVE families but do not fabricate CVE IDs." "$ev" || return 0
}

# ---- Phase 06: AD attack-surface narrative --------------------------------
# Privacy: hash files are NEVER sent — only their counts.
ai_bridge_06() {
  ai_available || { log "AI off — skipping phase-06 analysis."; return 0; }
  local O="$RUN/06-ad-recon"
  local kr ar tr
  kr=$(_ai_count "$O/kerberoast_hashes.txt"); ar=$(_ai_count "$O/asrep_hashes.txt"); tr=$(_ai_count "$O/timeroast_hashes.txt")
  local ev; ev=$( {
    printf 'Collected (for OFFLINE cracking — hashes NOT included):\n'
    printf '  kerberoast hashes: %s\n  asrep hashes: %s\n  timeroast hashes: %s\n' "$kr" "$ar" "$tr"
    _ai_cat "ADCS vulnerable templates" "$O/adcs_summary.txt"
    _ai_cat "LDAP description creds" "$O/ldap/desc_creds.txt"
    _ai_cat "Delegation (findDelegation)" "$O/findDelegation.txt"
    _ai_cat "SCCM/MECM" "$O/sccm.txt"
    _ai_cat "Validated users" "$O/valid_users.txt"
    [[ -d "$O/bloodhound" ]] && printf '\nBloodHound collection present: %s\n' "$O/bloodhound"
  } | _ai_bound )
  _ai_phase 06-ad-recon "Phase 06 — AD Attack Surface" "$(_schema_generic)" \
    "$_AI_PERSONA Focus: build a plain-English picture of the AD attack surface —
roastable accounts, ADCS ESC templates, delegation issues, credentials in LDAP
descriptions — and the most likely privilege-escalation paths. Hashes are
collected for offline cracking; reason from the counts, not the hashes." "$ev" || return 0
}

# ---- Phase 07: vuln-detection correlation ---------------------------------
ai_bridge_07() {
  ai_available || { log "AI off — skipping phase-07 analysis."; return 0; }
  local O="$RUN/07-vuln"
  local ev; ev=$( {
    _ai_cat "SMB vuln checks" "$O/smb_vuln_summary.txt"
    _ai_cat "netexec vuln modules" "$O/nxc_vuln_summary.txt"
    _ai_cat "SMBGhost" "$O/smbghost.txt"
    _ai_cat "BlueKeep" "$O/bluekeep.txt"
    _ai_cat "Critical web CVE sweep" "$O/nuclei_critical.txt"
    _ai_cat "SNMP hits" "$O/snmp_hits.txt"
    _ai_cat "TLS audit" "$O/tls_audit.txt"
  } | _ai_bound )
  _ai_phase 07-vuln "Phase 07 — Vulnerability Correlation" "$(_schema_generic)" \
    "$_AI_PERSONA Focus: correlate the non-exploitative detections into a
prioritised picture (e.g. EternalBlue + signing-disabled + reachable shares =
elevated risk). Call out false-positive-prone checks that need manual
validation before reporting." "$ev" || return 0
}

# ==========================================================================
# Phase 08: AI executive summary. Reads the just-built REPORT.md and injects
# a prioritised executive summary near the top.
# ==========================================================================
ai_exec_summary() {
  ai_available || { log "AI off — skipping AI executive summary."; return 0; }
  local REPORT="$RUN/REPORT.md"
  [[ -s "$REPORT" ]] || { warn "AI: REPORT.md not found — run the markdown task first."; return 0; }

  local ev; ev=$( {
    _ai_cat "Consolidated recon report" "$REPORT"
    _ai_cat_glob "Per-phase AI analysis" "$RUN/ai"/0*-*.json
  } | _ai_bound )

  log "AI[exec]: generating executive summary from REPORT.md ..."
  _ai_json exec-summary \
    "$_AI_PERSONA You are now writing the EXECUTIVE SUMMARY for the engagement
report aimed at both technical leads and management. Synthesise across all
phases into a prioritised, business-relevant picture. Return ONLY the requested
JSON. Be specific to the hosts/findings in the evidence." \
    "$ev" "$(_schema_exec)" || return 0

  local j="$RUN/ai/exec-summary.json" md="$RUN/ai/executive_summary.md"
  {
    echo "## AI Executive Summary"; echo
    _ai_banner; echo
    printf '**Overall risk: %s**\n\n' "$(jq -r '.overall_risk' "$j")"
    jq -r '.executive_summary' "$j"; echo
    echo "### Top risks (AI-prioritised)"; echo
    echo "| # | Severity | Finding | Business impact | Remediation |"
    echo "|---|----------|---------|-----------------|-------------|"
    jq -r '.top_risks[]? | "| \(.rank) | \(.severity) | \(.finding) | \(.business_impact) | \(.remediation) |"' "$j"
    echo
    echo "### Likely attack path"; echo
    jq -r '.attack_path_narrative' "$j"; echo
    echo "### Recommended actions"; echo
    jq -r '.recommended_actions[]? | "- \(.)"' "$j"
    echo
  } > "$md"

  # Inject the AI summary into REPORT.md, just before "## Asset Summary".
  if grep -q '^## Asset Summary' "$REPORT"; then
    awk -v f="$md" '
      /^## Asset Summary/ && !done { while ((getline l < f) > 0) print l; print ""; done=1 }
      { print }
    ' "$REPORT" > "$REPORT.tmp" && mv "$REPORT.tmp" "$REPORT"
  else
    cat "$md" >> "$REPORT"
  fi
  ok "AI[exec]: executive summary -> $md (also injected into REPORT.md)"
}
