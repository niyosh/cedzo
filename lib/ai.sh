#!/usr/bin/env bash
# ==========================================================================
# lib/ai.sh  -  LLM-backed analysis layer (sourced by lib/common.sh).
#
# Multi-provider: AI_PROVIDER selects anthropic | openai | gemini | ollama.
# A single dispatcher (_ai_request) builds the provider-specific body, posts it,
# and extracts the text. Anthropic/OpenAI/Ollama use native structured outputs
# (same JSON-Schema dialect); Gemini uses JSON mode with the schema in-prompt.
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
# Transport is raw HTTP via curl + jq (this is a shell project). Every response
# is coerced to JSON and validated before use.
# ==========================================================================

# ---- Provider resolution --------------------------------------------------
# Default model per provider (AI_MODEL overrides). Ollama default favours a
# capable-but-local model; see README for sizing guidance.
_ai_model() {
  if [[ -n "${AI_MODEL:-}" ]]; then printf '%s' "$AI_MODEL"; return; fi
  case "${AI_PROVIDER:-none}" in
    anthropic) printf 'claude-opus-4-8' ;;
    openai)    printf 'gpt-5.5' ;;
    gemini)    printf 'gemini-3.5-flash' ;;
    ollama)    printf 'qwen3:30b-a3b' ;;
    *)         printf 'claude-opus-4-8' ;;
  esac
}

# Default API base per provider (AI_BASE_URL overrides).
_ai_base() {
  if [[ -n "${AI_BASE_URL:-}" ]]; then printf '%s' "${AI_BASE_URL%/}"; return; fi
  case "${AI_PROVIDER:-none}" in
    anthropic) printf 'https://api.anthropic.com' ;;
    openai)    printf 'https://api.openai.com' ;;
    gemini)    printf 'https://generativelanguage.googleapis.com' ;;
    ollama)    printf 'http://localhost:11434' ;;
    *)         printf 'https://api.anthropic.com' ;;
  esac
}

# ---- Availability gate ----------------------------------------------------
ai_available() {
  have curl || { warn "AI: curl not found — skipping AI analysis."; return 1; }
  have jq   || { warn "AI: jq not found — skipping AI analysis."; return 1; }
  case "${AI_PROVIDER:-none}" in
    anthropic) [[ -n "${ANTHROPIC_API_KEY:-}" ]] || { warn "AI: ANTHROPIC_API_KEY is empty — skipping."; return 1; } ;;
    openai)    [[ -n "${OPENAI_API_KEY:-}"    ]] || { warn "AI: OPENAI_API_KEY is empty — skipping.";    return 1; } ;;
    gemini)    [[ -n "${GEMINI_API_KEY:-}"    ]] || { warn "AI: GEMINI_API_KEY is empty — skipping.";    return 1; } ;;
    ollama)    : ;;  # local; no key. Reachability is checked on first call.
    none)      return 1 ;;
    *)         warn "AI: unknown AI_PROVIDER='${AI_PROVIDER}' (use anthropic|openai|gemini|ollama)."; return 1 ;;
  esac
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

# ---- HTTP transport (provider dispatcher) ---------------------------------
# _ai_request <name> <system> <user> <schema>  ->  prints assistant text.
# Builds the provider-specific request, POSTs with retries, extracts the text
# payload. Logs request+response under $RUN/ai/log. All four providers are
# asked for JSON; Anthropic/OpenAI/Ollama use native structured outputs (same
# JSON-Schema dialect), Gemini uses JSON mode with the schema given in-prompt.
_ai_request() {
  local name="$1" sys="$2" usr="$3" schema="$4"
  local provider="${AI_PROVIDER:-none}" model base body url ctype extract
  local logd="$RUN/ai/log"; mkdir -p "$logd"
  model="$(_ai_model)"; base="$(_ai_base)"
  local -a hdr=(-H "content-type: application/json")

  case "$provider" in
    anthropic)
      url="$base/v1/messages"
      hdr+=(-H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01")
      extract='[.content[]? | select(.type=="text") | .text] | join("")'
      body=$(jq -n --arg m "$model" --argjson mt "${AI_MAX_TOKENS:-8000}" --arg eff "${AI_EFFORT:-high}" \
             --arg sys "$sys" --arg usr "$usr" --argjson schema "$schema" \
             '{ model:$m, max_tokens:$mt, thinking:{type:"adaptive"}, system:$sys,
                output_config:{ effort:$eff, format:{ type:"json_schema", schema:$schema } },
                messages:[ {role:"user", content:$usr} ] }') ;;
    openai)
      url="$base/v1/chat/completions"
      hdr+=(-H "authorization: Bearer $OPENAI_API_KEY")
      extract='.choices[0].message.content // empty'
      # GPT-5.x / reasoning models require max_completion_tokens (not max_tokens);
      # reasoning effort defaults to medium (left unset to stay valid across models).
      body=$(jq -n --arg m "$model" --argjson mt "${AI_MAX_TOKENS:-8000}" \
             --arg sys "$sys" --arg usr "$usr" --argjson schema "$schema" \
             '{ model:$m, max_completion_tokens:$mt,
                messages:[ {role:"system", content:$sys}, {role:"user", content:$usr} ],
                response_format:{ type:"json_schema",
                  json_schema:{ name:"report", strict:true, schema:$schema } } }') ;;
    gemini)
      url="$base/v1beta/models/$model:generateContent"
      hdr+=(-H "x-goog-api-key: $GEMINI_API_KEY")
      extract='[.candidates[0].content.parts[]?.text] | join("")'
      # Gemini's responseSchema uses a different dialect; instead give the schema
      # in-prompt and force JSON output via responseMimeType.
      body=$(jq -n --arg m "$model" --argjson mt "${AI_MAX_TOKENS:-8000}" \
             --arg sys "$sys" --arg usr "$usr" --arg schema "$schema" \
             '{ systemInstruction:{ parts:[ {text: ($sys + "\nReturn ONLY a JSON object that validates against this JSON Schema:\n" + $schema)} ] },
                contents:[ {role:"user", parts:[ {text:$usr} ]} ],
                generationConfig:{ responseMimeType:"application/json", maxOutputTokens:$mt } }') ;;
    ollama)
      url="$base/api/chat"
      extract='.message.content // empty'
      # num_ctx MUST be set — Ollama defaults to ~4K and silently truncates the
      # large evidence digests otherwise. Raise AI_OLLAMA_NUM_CTX for phase 09.
      body=$(jq -n --arg m "$model" --argjson np "${AI_MAX_TOKENS:-8000}" \
             --argjson nc "${AI_OLLAMA_NUM_CTX:-40960}" \
             --arg sys "$sys" --arg usr "$usr" --argjson schema "$schema" \
             '{ model:$m, stream:false, format:$schema,
                options:{ num_predict:$np, num_ctx:$nc },
                messages:[ {role:"system", content:$sys}, {role:"user", content:$usr} ] }') ;;
    *) warn "AI[$name]: unsupported provider '$provider'"; return 1 ;;
  esac
  [[ -n "$body" ]] || { warn "AI[$name]: failed to build request body"; return 1; }
  printf '%s' "$body" > "$logd/$name.req.json"

  local attempt resp errmsg
  for attempt in 1 2 3; do
    resp=$(printf '%s' "$body" | curl -sS --max-time "${AI_TIMEOUT:-180}" \
        "${hdr[@]}" "$url" --data-binary @- 2>/dev/null) || resp=""
    printf '%s' "$resp" > "$logd/$name.resp.json"
    if [[ -z "$resp" ]]; then
      warn "AI[$name]: empty/failed response from $provider (attempt $attempt/3)" >&2; sleep 3; continue
    fi
    errmsg=$(printf '%s' "$resp" | jq -r 'if (type=="object" and has("error")) then (.error.message // (.error|tostring)) else empty end' 2>/dev/null || true)
    if [[ -n "$errmsg" ]]; then
      if printf '%s' "$errmsg" | grep -qiE 'rate|overload|quota|exhaust|unavailable|timeout|try again|50[0-9]'; then
        warn "AI[$name]: $provider transient error: $errmsg (retry $attempt/3)" >&2; sleep 5; continue
      fi
      err "AI[$name]: $provider error: $errmsg"; return 1
    fi
    printf '%s' "$resp" | jq -r "$extract"
    return 0
  done
  warn "AI[$name]: gave up after 3 attempts." >&2; return 1
}

# _ai_json <name> <system> <user-evidence> <schema-json>
# Writes validated JSON to $RUN/ai/<name>.json. Returns 1 on any failure.
_ai_json() {
  local name="$1" system="$2" user="$3" schema="$4"
  local dir="$RUN/ai" logd="$RUN/ai/log"; mkdir -p "$dir" "$logd"
  local text
  text=$(_ai_request "$name" "$system" "$user" "$schema") || return 1
  # Models occasionally wrap JSON in ```json fences — strip them defensively.
  text=$(printf '%s' "$text" | sed -E 's/^```[a-zA-Z]*[[:space:]]*//; s/```[[:space:]]*$//')
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
  printf '> ⚠️ **AI-generated** (%s / `%s`). Triage guidance only — not a CVSS score and not ground truth. Validate every item against the linked evidence before acting.\n' "${AI_PROVIDER:-?}" "$(_ai_model)"
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
  log "AI[$name]: analysing $(printf '%s' "$evidence" | wc -c) bytes via ${AI_PROVIDER}/$(_ai_model) ..."
  _ai_json "$name" "$system" "$evidence" "$schema" || return 1
  _ai_render_generic "$RUN/ai/$name.json" "$RUN/ai/$name.md" "$title"
  ok "AI[$name]: analysis -> $RUN/ai/$name.md"
  return 0
}

# ---- Offline pack ---------------------------------------------------------
# When no AI provider is configured (or it's unavailable), write a single
# paste-ready prompt file so the operator can run the analysis manually in any
# chat UI / local model and drop the JSON reply back for rendering. Needs no
# jq/curl/key — just the (already redacted) evidence + schema + instructions.
_ai_offline_write() {
  local name="$1" title="$2" system="$3" evidence="$4" schema="$5" savehint="$6"
  local d="$RUN/ai/offline"; mkdir -p "$d"
  local f="$d/$name.prompt.md"
  {
    echo "# CEDZO — manual AI prompt: $title"
    echo
    echo "No AI provider is configured (\`AI_PROVIDER=none\`), so this run could not"
    echo "produce the AI analysis automatically. To generate it by hand:"
    echo
    echo "  1. Copy everything below the \`=== SYSTEM ===\` line into any AI"
    echo "     (ChatGPT / Claude / Gemini / a local model)."
    echo "  2. Save the JSON it returns to:"
    echo
    echo "         $savehint"
    echo
    echo "  3. Re-render the report:  ./run.sh 09"
    echo
    echo "The evidence below is already redacted and bounded the same way it would"
    echo "be sent automatically. Review it before pasting into a third-party service."
    echo
    echo "=== SYSTEM ==="
    printf '%s\n' "$system"
    echo
    echo "Return ONLY a JSON object that validates against this JSON Schema:"
    echo '```json'
    printf '%s\n' "$schema"
    echo '```'
    echo
    echo "=== EVIDENCE ==="
    printf '%s\n' "$evidence"
  } > "$f"
  warn "AI off — wrote manual prompt pack: $f"
  log  "  → paste it into any AI, save the JSON reply to: $savehint, then: ./run.sh 09"
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
    _ai_cat_glob "Earlier-phase AI findings" "$RUN/ai"/0*-*.json
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
    _ai_cat_glob "Earlier-phase AI findings" "$RUN/ai"/0*-*.json
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
    _ai_cat_glob "Earlier-phase AI findings" "$RUN/ai"/0*-*.json
  } | _ai_bound )
  _ai_phase 06-ad-recon "Phase 06 — AD Attack Surface" "$(_schema_generic)" \
    "$_AI_PERSONA Focus: build a plain-English picture of the AD attack surface —
roastable accounts, ADCS ESC templates, delegation issues, credentials in LDAP
descriptions — and the most likely privilege-escalation paths. Hashes are
collected for offline cracking; reason from the counts, not the hashes. Use the
earlier-phase AI findings to connect AD weaknesses to hosts/services already
flagged elsewhere." "$ev" || return 0
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
    _ai_cat_glob "Earlier-phase AI findings" "$RUN/ai"/0*-*.json
  } | _ai_bound )
  _ai_phase 07-vuln "Phase 07 — Vulnerability Correlation" "$(_schema_generic)" \
    "$_AI_PERSONA Focus: correlate the non-exploitative detections WITH the
earlier-phase AI findings into a prioritised picture (e.g. EternalBlue +
signing-disabled + a reachable share + a roastable admin = a chain worth
flagging). Call out false-positive-prone checks that need manual validation
before reporting." "$ev" || return 0
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

# ==========================================================================
# Final client deliverable: AI authors a de-duplicated vulnerability register
# + attack chains, written to $RUN/ai/xlsx-report.json. The phase-09 script
# then renders it into the house .xlsx via reporting/xlsx_report.py.
# ==========================================================================
_schema_xlsx() {
cat <<'JSON'
{
  "type": "object", "additionalProperties": false,
  "properties": {
    "vulnerabilities": {
      "type": "array",
      "items": {
        "type": "object", "additionalProperties": false,
        "properties": {
          "severity":       { "type": "string", "enum": ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] },
          "name":           { "type": "string" },
          "cve_ref":        { "type": "string" },
          "category":       { "type": "string" },
          "affected_hosts": { "type": "string" },
          "description":    { "type": "string" },
          "impact":         { "type": "string" },
          "remediation":    { "type": "string" },
          "cvss":           { "type": "string" },
          "tool_source":    { "type": "string" }
        },
        "required": ["severity","name","cve_ref","category","affected_hosts","description","impact","remediation","cvss","tool_source"]
      }
    },
    "attack_chains": {
      "type": "array",
      "items": {
        "type": "object", "additionalProperties": false,
        "properties": {
          "chain_name":         { "type": "string" },
          "initial_access":     { "type": "string" },
          "lateral_escalation": { "type": "string" },
          "impact":             { "type": "string" },
          "findings_used":      { "type": "string" },
          "severity":           { "type": "string", "enum": ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] }
        },
        "required": ["chain_name","initial_access","lateral_escalation","impact","findings_used","severity"]
      }
    }
  },
  "required": ["vulnerabilities","attack_chains"]
}
JSON
}

# Collect (almost) everything the run produced, redacted + bounded, and have
# Claude author the final findings register. Larger token/timeout budget than
# the per-phase calls since this is the whole engagement in one shot.
ai_xlsx_report() {
  local ev; ev=$( {
    _ai_cat "Consolidated report" "$RUN/REPORT.md"
    _ai_cat_glob "Per-phase AI findings" "$RUN/ai"/0*-*.json
    [[ -s "$RUN/ai/exec-summary.json" ]] && _ai_cat "Executive summary" "$RUN/ai/exec-summary.json"
    _ai_cat "07 SMB vuln"        "$RUN/07-vuln/smb_vuln_summary.txt"
    _ai_cat "07 netexec vuln"    "$RUN/07-vuln/nxc_vuln_summary.txt"
    _ai_cat "07 SMBGhost"        "$RUN/07-vuln/smbghost.txt"
    _ai_cat "07 BlueKeep"        "$RUN/07-vuln/bluekeep.txt"
    _ai_cat "07 nuclei critical" "$RUN/07-vuln/nuclei_critical.txt"
    _ai_cat "07 TLS audit"       "$RUN/07-vuln/tls_audit.txt"
    _ai_cat "07 SNMP hits"       "$RUN/07-vuln/snmp_hits.txt"
    _ai_cat "06 ADCS"            "$RUN/06-ad-recon/adcs_summary.txt"
    _ai_cat "06 LDAP desc creds" "$RUN/06-ad-recon/ldap/desc_creds.txt"
    _ai_cat "06 delegation"      "$RUN/06-ad-recon/findDelegation.txt"
    _ai_cat "06 SCCM"            "$RUN/06-ad-recon/sccm.txt"
    _ai_cat_glob "03 shares"     "$RUN/03-smb-ad"/shares*
    _ai_cat "03 GPP creds"       "$RUN/03-smb-ad/gpp_creds.txt"
    _ai_cat "03 NFS exports"     "$RUN/03-smb-ad/nfs_exports.txt"
    _ai_cat_glob "03 anon LDAP"  "$RUN/03-smb-ad"/ldap_anon_*.txt
    _ai_cat_glob "03 DNS AXFR"   "$RUN/03-smb-ad"/axfr_*.txt
    _ai_cat "04 nuclei"          "$RUN/04-web/nuclei.txt"
    _ai_cat "04 nuclei (AI)"     "$RUN/04-web/nuclei_ai.txt"
    _ai_cat "04 exposures"       "$RUN/04-web/exposures.txt"
    _ai_cat "04 httpx"           "$RUN/04-web/httpx.txt"
    _ai_cat "05 DB NSE"          "$RUN/05-db/db_nse.nmap"
    _ai_cat "02 host ports"      "$RUN/02-portscan/host_ports.txt"
  } | head -c "${AI_REPORT_MAX_CHARS:-400000}" )
  [[ -n "${ev//[[:space:]]/}" ]] || { warn "AI[xlsx]: no evidence found — nothing to report."; return 0; }

  local sys="$_AI_PERSONA
You are producing the FINAL client deliverable: a de-duplicated vulnerability
register plus realistic attack chains, to be rendered into the standard report
spreadsheet. Return ONLY the requested JSON.
Rules:
- One row per DISTINCT vulnerability/finding. Merge the same issue across hosts
  into one row and list every affected host in affected_hosts (newline-separated).
- severity = realistic impact on an internal engagement.
- cvss = best-fit CVSS 3.1 base score as a string (e.g. \"9.8\"); empty string
  if not applicable. cve_ref = CVE id or technique tag (ESC1, MS17-010, ...) or
  empty. NEVER invent CVE ids unsupported by the evidence.
- tool_source = the tool that produced the finding (from the evidence).
- attack_chains = realistic initial-access -> escalation -> impact paths that
  CHAIN findings together; reference the findings in findings_used. These are
  hypotheses derived from recon (nothing was exploited) — phrase accordingly.
- Ground everything strictly in the evidence; never invent hosts or results."

  if ai_available 2>/dev/null; then
    log "AI[xlsx]: authoring the vulnerability register from $(printf '%s' "$ev" | wc -c) bytes via ${AI_PROVIDER}/$(_ai_model) ..."
    # Wider budgets than per-phase calls (dynamic-scoped into _ai_json/_ai_request).
    local AI_MAX_TOKENS="${AI_REPORT_MAX_TOKENS:-16000}" AI_TIMEOUT="${AI_REPORT_TIMEOUT:-300}"
    _ai_json xlsx-report "$sys" "$ev" "$(_schema_xlsx)" || return 1
    ok "AI[xlsx]: findings JSON -> $RUN/ai/xlsx-report.json"
  else
    _ai_offline_write xlsx-report "Final vulnerability register + attack chains" \
      "$sys" "$ev" "$(_schema_xlsx)" "loot/run/ai/xlsx-report.json"
  fi
  return 0
}
