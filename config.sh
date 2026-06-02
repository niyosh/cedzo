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
