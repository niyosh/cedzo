#!/usr/bin/env bash
# ==========================================================================
# config.sh  -  Central configuration. EDIT THIS before running anything.
#
# This kit is RECON-ONLY: discovery, enumeration, fingerprinting, and
# non-exploitative vulnerability DETECTION. It performs no password spraying,
# no credential brute force, and no service-disruptive actions.
# ==========================================================================

# --- Scope -----------------------------------------------------------------
# One IP, range, or CIDR per line. Comments (#) and blanks ignored.
SCOPE_FILE="${SCOPE_FILE:-scope.txt}"

# Where all output lands (timestamped run dir is created underneath).
OUTPUT_BASE="${OUTPUT_BASE:-./loot}"

# --- Performance -----------------------------------------------------------
THREADS="${THREADS:-20}"        # parallel per-host tasks
MIN_RATE="${MIN_RATE:-2000}"    # nmap packet rate (lower if unstable links)
NMAP_TIMING="${NMAP_TIMING:-4}" # -T value (4 = aggressive, 3 = polite)

# --- Active Directory credentials (OPTIONAL) -------------------------------
# Leave blank for fully unauthenticated recon. Supply read-only creds to enable
# authenticated directory enumeration (LDAP dump, BloodHound, SPN/AS-REP
# collection). No credentials are ever sprayed or brute-forced.
DOMAIN="${DOMAIN:-}"            # e.g. CORP.LOCAL
DC_IP="${DC_IP:-}"             # e.g. 10.10.10.10
USERNAME="${USERNAME:-}"
PASSWORD="${PASSWORD:-}"
NTHASH="${NTHASH:-}"           # NTLM hash for pass-the-hash auth (instead of PASSWORD)

# --- Wordlists -------------------------------------------------------------
WEB_WORDLIST="${WEB_WORDLIST:-/usr/share/wordlists/dirb/common.txt}"
USER_WORDLIST="${USER_WORDLIST:-/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt}"

# --- Behaviour flags -------------------------------------------------------
SKIP_UDP="${SKIP_UDP:-false}"           # UDP scans are slow; set true to skip
SCREENSHOTS="${SCREENSHOTS:-true}"      # web screenshots via gowitness
BLOODHOUND="${BLOODHOUND:-true}"        # phase 06 BloodHound collection (needs read-only creds); set false to skip

# --- Web crawling (katana + feroxbuster, feeds nuclei) ---------------------
WEB_CRAWL="${WEB_CRAWL:-true}"          # crawl + content-discover before nuclei
KATANA_DEPTH="${KATANA_DEPTH:-2}"       # katana crawl depth (raise for deeper apps)

# --- nuclei ----------------------------------------------------------------
# 'info' templates are by far the noisiest and balloon scan time/requests.
# Drop 'info,' here for much faster, higher-signal scans.
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-info,low,medium,high,critical}"
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-10}"  # per-request timeout (s); guards fragile hosts

# --- File services ---------------------------------------------------------
NFS_MOUNT="${NFS_MOUNT:-true}"          # read-only mount NFS exports to list top-level contents

# --- vhost discovery (optional) --------------------------------------------
# Set a wordlist to enable ffuf vhost brute against web hosts (uses $DOMAIN).
VHOST_WORDLIST="${VHOST_WORDLIST:-}"

# --- Extra recon engines (from the tool arsenal) ---------------------------
WEB_CMS="${WEB_CMS:-false}"            # CMSeeK CMS enumeration in the web phase
SECRET_SCAN="${SECRET_SCAN:-true}"     # noseyparker secret-scan over collected loot (phase 08)

# ==========================================================================
# --- AI augmentation (Claude) ---------------------------------------------
# OPT-IN. When enabled, each phase sends a bounded, redacted digest of its
# OWN output to Claude and writes structured analysis to $RUN/ai/. The AI is
# a TRIAGE layer only: it ranks, correlates, and suggests next steps. It does
# NOT scan, exploit, or execute anything — tool output stays authoritative,
# and nothing the model returns is ever turned into a command.
#
# To turn it on:   export AI_PROVIDER=anthropic
#                  export ANTHROPIC_API_KEY=sk-ant-...
# Leave AI_PROVIDER=none (default) and the kit behaves exactly as before.
# ==========================================================================
AI_PROVIDER="${AI_PROVIDER:-none}"          # none | anthropic
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"  # your enterprise/standard key (read from env)
AI_BASE_URL="${ANTHROPIC_BASE_URL:-https://api.anthropic.com}"
AI_MODEL="${AI_MODEL:-claude-opus-4-8}"     # analysis model
AI_EFFORT="${AI_EFFORT:-high}"              # low | medium | high | max (Opus-tier)
AI_MAX_TOKENS="${AI_MAX_TOKENS:-8000}"      # max output tokens per analysis call
AI_TIMEOUT="${AI_TIMEOUT:-180}"            # per-request curl timeout (seconds)

# Input bounding — keep per-call cost/latency sane on large runs.
AI_MAX_INPUT_CHARS="${AI_MAX_INPUT_CHARS:-160000}" # total evidence per call (~40k tok)
AI_PER_FILE_CHARS="${AI_PER_FILE_CHARS:-24000}"    # cap any single evidence file

# Privacy controls — this is client data leaving your box. Redaction masks the
# obvious secrets (passwords, hashes, keys) before anything is sent. Raw hash
# files and the noseyparker secrets report are NEVER sent regardless.
AI_REDACT_SECRETS="${AI_REDACT_SECRETS:-true}"

# Per-feature toggles.
AI_NUCLEI_TAGS="${AI_NUCLEI_TAGS:-true}"   # run an extra AI-targeted nuclei pass (additive)

# Final client XLSX report (phase 09). Bigger budgets — whole engagement in one
# call. Needs python3 + openpyxl (auto-installed by phase 09 if missing).
AI_REPORT_MAX_CHARS="${AI_REPORT_MAX_CHARS:-400000}"  # evidence digest cap (~100k tok)
AI_REPORT_MAX_TOKENS="${AI_REPORT_MAX_TOKENS:-16000}" # max output tokens for the register
AI_REPORT_TIMEOUT="${AI_REPORT_TIMEOUT:-300}"        # curl timeout for the report call (s)
