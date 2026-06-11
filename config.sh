#!/usr/bin/env bash
# ==========================================================================
# config.sh  -  Central configuration. EDIT THIS before running anything.
#
# This kit is RECON-ONLY: discovery, enumeration, fingerprinting, and
# non-exploitative vulnerability DETECTION. It performs no exploitation, no
# password spraying, no credential brute force, and no service-disruptive
# actions.
#
# The kit runs in one of two MODES, chosen by run.sh (internal | external) and
# exported as KIT_MODE:
#   internal  -  internal network recon (the original CEDZO behaviour)
#   external  -  external attack-surface recon (the original EXDZO behaviour)
# Settings below that apply to only one mode are tagged [internal] / [external];
# the other mode simply ignores them. Performance defaults differ per mode.
# ==========================================================================

# Default to internal when a phase is launched standalone (run.sh sets this).
KIT_MODE="${KIT_MODE:-internal}"

# --- Scope -----------------------------------------------------------------
# One target per line. Comments (#) and blanks ignored.
#   internal : an IP, range, or CIDR.
#   external : a public IP, IP range, CIDR, or a root DOMAIN. Domains are
#              expanded by the OSINT phase (subdomains -> resolved IPs) and the
#              resolved hosts are folded back into scope.
SCOPE_FILE="${SCOPE_FILE:-scope.txt}"

# Where all output lands (a mode-specific 'run-<mode>' dir is created
# underneath; runs resume).
OUTPUT_BASE="${OUTPUT_BASE:-./loot}"

# --- Engagement identity ---------------------------------------------------
# [external] A primary root domain for the target org (drives subdomain/CT/email
# checks). Optional — leave blank for an IP-only engagement. Extra domains can
# simply be listed in scope.txt.
TARGET_DOMAIN="${TARGET_DOMAIN:-}"     # e.g. example.com

# --- Performance -----------------------------------------------------------
# External scanning crosses someone else's links and IDS, so its defaults are
# deliberately gentler than an internal run. Raise only with authorisation.
if [[ "$KIT_MODE" == "external" ]]; then
  THREADS="${THREADS:-15}"        # parallel per-host tasks
  MIN_RATE="${MIN_RATE:-500}"     # nmap packet rate (KEEP LOW on the Internet)
  NMAP_TIMING="${NMAP_TIMING:-3}" # -T value (3 = polite; 4 = aggressive)
  SKIP_UDP="${SKIP_UDP:-true}"    # external UDP is slow + often filtered
else
  THREADS="${THREADS:-20}"        # parallel per-host tasks
  MIN_RATE="${MIN_RATE:-2000}"    # nmap packet rate (lower if unstable links)
  NMAP_TIMING="${NMAP_TIMING:-4}" # -T value (4 = aggressive, 3 = polite)
  SKIP_UDP="${SKIP_UDP:-false}"   # UDP scans are slow; set true to skip
fi
MAX_RETRIES="${MAX_RETRIES:-2}"   # [external] nmap --max-retries (drop on lossy WAN)

# [external] Restrict the TCP scan to a fast, high-signal external port set
# instead of all 65535. Set TCP_FULL=true for an exhaustive -p- sweep.
TCP_FULL="${TCP_FULL:-false}"
TCP_TOP_PORTS="${TCP_TOP_PORTS:-1000}"  # nmap --top-ports when TCP_FULL=false

# --- Active Directory credentials (OPTIONAL) -------------------------------
# [internal] Leave blank for fully unauthenticated recon. Supply read-only creds
# to enable authenticated directory enumeration (LDAP dump, BloodHound, SPN/
# AS-REP collection). No credentials are ever sprayed or brute-forced.
DOMAIN="${DOMAIN:-}"            # e.g. CORP.LOCAL
DC_IP="${DC_IP:-}"             # e.g. 10.10.10.10
USERNAME="${USERNAME:-}"
PASSWORD="${PASSWORD:-}"
NTHASH="${NTHASH:-}"           # NTLM hash for pass-the-hash auth (instead of PASSWORD)

# --- Wordlists -------------------------------------------------------------
WEB_WORDLIST="${WEB_WORDLIST:-/usr/share/wordlists/dirb/common.txt}"
USER_WORDLIST="${USER_WORDLIST:-/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt}"  # [internal]
DNS_WORDLIST="${DNS_WORDLIST:-/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt}"        # [external]
# Set a wordlist to enable ffuf vhost brute against web hosts (uses $DOMAIN /
# $TARGET_DOMAIN).
VHOST_WORDLIST="${VHOST_WORDLIST:-}"

# --- Behaviour flags -------------------------------------------------------
SCREENSHOTS="${SCREENSHOTS:-true}"      # web screenshots via gowitness
BLOODHOUND="${BLOODHOUND:-true}"        # [internal] phase 06 BloodHound collection (needs read-only creds)
NFS_MOUNT="${NFS_MOUNT:-true}"          # [internal] read-only mount NFS exports to list top-level contents
ALLOW_BANNER_GRAB="${ALLOW_BANNER_GRAB:-true}"  # [external] light banner reads on exposed services (no auth attempts)

# --- OSINT / passive recon -------------------------------------------------
# [external]
SUBDOMAIN_ENUM="${SUBDOMAIN_ENUM:-true}"   # subfinder/amass/crt.sh subdomain discovery
PASSIVE_ONLY="${PASSIVE_ONLY:-false}"      # true = OSINT + passive sources only; skip active scans
RESOLVE_SUBDOMAINS="${RESOLVE_SUBDOMAINS:-true}" # resolve discovered subdomains and fold IPs into scope
AMASS_ACTIVE="${AMASS_ACTIVE:-false}"      # amass active enum (DNS brute / zone walk); off = passive
CT_LOGS="${CT_LOGS:-true}"                 # certificate-transparency lookups (crt.sh)

# Optional passive-source API keys (used by subfinder/shodan if present).
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
CENSYS_API_ID="${CENSYS_API_ID:-}"
CENSYS_API_SECRET="${CENSYS_API_SECRET:-}"
SECURITYTRAILS_API_KEY="${SECURITYTRAILS_API_KEY:-}"

# --- Web crawling (katana + feroxbuster, feeds nuclei) ---------------------
WEB_CRAWL="${WEB_CRAWL:-true}"          # crawl + content-discover before nuclei
KATANA_DEPTH="${KATANA_DEPTH:-2}"       # katana crawl depth (raise for deeper apps)

# --- nuclei ----------------------------------------------------------------
# 'info' templates are by far the noisiest and balloon scan time/requests.
# Drop 'info,' here for much faster, higher-signal scans.
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-info,low,medium,high,critical}"
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-10}"  # per-request timeout (s); guards fragile hosts
NUCLEI_RATELIMIT="${NUCLEI_RATELIMIT:-100}"  # [external] global requests/sec cap (be gentle)

# --- Subdomain takeover + cloud --------------------------------------------
# [external]
TAKEOVER_CHECK="${TAKEOVER_CHECK:-true}"   # dangling-CNAME / subdomain-takeover detection
CLOUD_BUCKETS="${CLOUD_BUCKETS:-true}"     # open S3/Azure/GCS bucket discovery (read-only listing)

# --- Extra recon engines ---------------------------------------------------
WEB_CMS="${WEB_CMS:-false}"            # [internal] CMSeeK CMS enumeration in the web phase
SECRET_SCAN="${SECRET_SCAN:-true}"     # noseyparker secret-scan over collected loot (phase 08)

# ==========================================================================
# --- AI augmentation (Claude) ---------------------------------------------
# OPT-IN. When enabled, each phase sends a bounded, redacted digest of its
# OWN output to an LLM and writes structured analysis to $RUN/ai/. The AI is
# a TRIAGE layer only: it ranks, correlates, and suggests next steps. It does
# NOT scan, exploit, or execute anything — tool output stays authoritative,
# and nothing the model returns is ever turned into a command.
#
# To turn it on:   export AI_PROVIDER=anthropic   (or openai | gemini | ollama)
#                  export ANTHROPIC_API_KEY=sk-ant-...   (key for chosen provider)
# Leave AI_PROVIDER=none (default) and the kit behaves exactly as before.
# ==========================================================================
AI_PROVIDER="${AI_PROVIDER:-none}"   # none | anthropic | openai | gemini | ollama

# API keys — only the SELECTED provider's key is needed. Ollama needs none.
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"
OPENAI_API_KEY="${OPENAI_API_KEY:-}"
GEMINI_API_KEY="${GEMINI_API_KEY:-}"

# Model + endpoint. Leave BLANK to use the per-provider defaults (all chosen to
# handle the kit's large context + strict-JSON workload — see README):
#   anthropic -> claude-opus-4-8        openai -> gpt-5.5
#   gemini    -> gemini-3.5-flash       ollama -> qwen3:30b-a3b  (256K ctx MoE)
# Ollama default base URL is http://localhost:11434 (override via AI_BASE_URL).
AI_MODEL="${AI_MODEL:-}"               # blank = provider default (see above)
AI_BASE_URL="${AI_BASE_URL:-}"         # blank = provider default endpoint
AI_EFFORT="${AI_EFFORT:-high}"         # anthropic only (low|medium|high|max); ignored elsewhere
AI_MAX_TOKENS="${AI_MAX_TOKENS:-8000}" # max output tokens per analysis call
AI_TIMEOUT="${AI_TIMEOUT:-180}"        # per-request curl timeout (seconds)

# Ollama only: context window. Ollama defaults to ~4K and SILENTLY TRUNCATES big
# inputs, so set it. 40960 covers the per-phase calls; raise toward 131072 for
# the full phase-09 digest (needs RAM) or lower AI_REPORT_MAX_CHARS to fit.
AI_OLLAMA_NUM_CTX="${AI_OLLAMA_NUM_CTX:-40960}"

# Input bounding — keep per-call cost/latency sane on large runs.
AI_MAX_INPUT_CHARS="${AI_MAX_INPUT_CHARS:-160000}" # total evidence per call (~40k tok)
AI_PER_FILE_CHARS="${AI_PER_FILE_CHARS:-24000}"    # cap any single evidence file

# Privacy controls — this is client data leaving your box. Redaction masks the
# obvious secrets (passwords, hashes, keys) before anything is sent. Raw hash
# files and the noseyparker secrets report are NEVER sent regardless.
AI_REDACT_SECRETS="${AI_REDACT_SECRETS:-true}"

# Per-feature toggles.
AI_NUCLEI_TAGS="${AI_NUCLEI_TAGS:-true}"   # let AI curate nuclei URLs + tags

# Final client XLSX report (phase 09). Bigger budgets — whole engagement in one
# call. Needs python3 + openpyxl (auto-installed by phase 09 if missing).
AI_REPORT_MAX_CHARS="${AI_REPORT_MAX_CHARS:-400000}"  # evidence digest cap (~100k tok)
AI_REPORT_MAX_TOKENS="${AI_REPORT_MAX_TOKENS:-16000}" # max output tokens for the register
AI_REPORT_TIMEOUT="${AI_REPORT_TIMEOUT:-300}"        # curl timeout for the report call (s)
