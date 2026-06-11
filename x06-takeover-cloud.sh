#!/usr/bin/env bash
# ==========================================================================
# 06-takeover-cloud.sh  -  Subdomain-takeover detection and cloud exposure.
# Finds dangling CNAMEs pointing at deprovisioned cloud services, open cloud
# storage buckets, and exposed source repositories.
#
# RECON ONLY: detection / fingerprinting. It does NOT claim/register any
# resource and does NOT download bucket contents — it only checks reachability
# and listability.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
OUT="$RUN/06-takeover"; mkdir -p "$OUT"; LOG="$OUT/takeover.log"
SUBS="$RUN/02-osint/subdomains.txt"

phase "Subdomain Takeover / Cloud Exposure"

# ---- Sub-task: dangling-CNAME enumeration ---------------------------------
# A CNAME that resolves to a third-party service host but does NOT resolve to
# an A record (NXDOMAIN at the target) is a classic takeover candidate.
t_dangling() {
  { have dig && [[ -s "$SUBS" ]]; } || { warn "dig missing or no subdomains — skipping."; return 0; }
  : > "$OUT/dangling_cnames.txt"
  log "Checking subdomains for dangling CNAMEs"
  local h cname a
  local FINGERPRINTS='amazonaws|cloudfront|herokuapp|herokudns|github.io|gitlab.io|azurewebsites|cloudapp.azure|trafficmanager|blob.core.windows|fastly|pantheon|wpengine|zendesk|desk.com|freshdesk|statuspage|surge.sh|bitbucket.io|readthedocs|ghost.io|helpscoutdocs|netlify|firebaseapp|s3-website|shopify|tumblr|wordpress.com|unbounce|cargocollective'
  while read -r h; do
    [[ -n "$h" ]] || continue
    cname=$(dig +short CNAME "$h" 2>/dev/null | head -1)
    [[ -n "$cname" ]] || continue
    a=$(dig +short "$h" A 2>/dev/null | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -1)
    if grep -qiE "$FINGERPRINTS" <<<"$cname"; then
      if [[ -z "$a" ]]; then
        printf '%s\tCNAME=%s\tNO A-record (likely takeover candidate)\n' "$h" "$cname" >> "$OUT/dangling_cnames.txt"
      else
        printf '%s\tCNAME=%s\tresolves (review service ownership)\n' "$h" "$cname" >> "$OUT/dangling_cnames.txt"
      fi
    fi
  done < "$SUBS"
  [[ -s "$OUT/dangling_cnames.txt" ]] && warn "Dangling/3rd-party CNAMEs -> $OUT/dangling_cnames.txt" \
    || ok "No dangling third-party CNAMEs found."
}

# ---- Sub-task: subdomain takeover detection (tooling) ---------------------
t_takeover() {
  [[ "${TAKEOVER_CHECK:-true}" == "true" && -s "$SUBS" ]] \
    || { warn "TAKEOVER_CHECK disabled or no subdomains — skipping."; return 0; }
  if have subzy; then
    log "subzy subdomain-takeover scan"
    subzy run --targets "$SUBS" --hide_fails 2>/dev/null | tee "$OUT/takeover.txt" || true
  elif have subjack; then
    log "subjack subdomain-takeover scan"
    subjack -w "$SUBS" -t 50 -timeout 20 -ssl -v -o "$OUT/takeover.txt" 2>/dev/null || true
  elif have nuclei; then
    log "nuclei takeover templates"
    nuclei -l "$SUBS" -tags takeover -severity medium,high,critical \
      -timeout "${NUCLEI_TIMEOUT:-10}" -rl "${NUCLEI_RATELIMIT:-100}" \
      -o "$OUT/takeover.txt" -stats 2>/dev/null || true
  else
    warn "No takeover tool (subzy/subjack/nuclei) — relying on dangling-CNAME check only."
    return 0
  fi
  [[ -s "$OUT/takeover.txt" ]] && warn "Takeover candidates -> $OUT/takeover.txt" \
    || ok "No subdomain-takeover candidates flagged by tooling."
}

# ---- Sub-task: cloud storage bucket discovery -----------------------------
# Derive candidate bucket names from the org/domain labels and check whether
# they exist and are publicly LISTABLE (read-only HEAD/GET of the index).
t_buckets() {
  [[ "${CLOUD_BUCKETS:-true}" == "true" ]] && have curl || { warn "CLOUD_BUCKETS disabled or curl missing — skipping."; return 0; }
  : > "$OUT/buckets.txt"
  # Build candidate names from domain labels + common suffixes.
  local labels=() d
  if [[ -s "$RUN/domain_targets.txt" ]]; then
    while read -r d; do labels+=("${d%%.*}"); done < "$RUN/domain_targets.txt"
  fi
  [[ -n "${TARGET_DOMAIN:-}" ]] && labels+=("${TARGET_DOMAIN%%.*}")
  [[ ${#labels[@]} -gt 0 ]] || { warn "No domain labels to derive bucket names — skipping."; return 0; }

  local suffixes=("" "-backup" "-backups" "-dev" "-prod" "-staging" "-assets" "-static" "-media" "-data" "-files" "-public" "-private" "-logs")
  local base sfx name url code
  log "Probing candidate cloud buckets (S3/GCS/Azure) for public listing"
  for base in $(printf '%s\n' "${labels[@]}" | sort -u); do
    for sfx in "${suffixes[@]}"; do
      name="${base}${sfx}"
      # AWS S3
      url="https://${name}.s3.amazonaws.com/"
      code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' "$url" 2>/dev/null || echo 000)
      [[ "$code" == "200" ]] && printf '%s\tS3\tPUBLIC-LISTABLE (200)\n' "$url" >> "$OUT/buckets.txt"
      [[ "$code" == "403" ]] && printf '%s\tS3\tEXISTS (403 — private)\n' "$url" >> "$OUT/buckets.txt"
      # Google Cloud Storage
      url="https://storage.googleapis.com/${name}/"
      code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' "$url" 2>/dev/null || echo 000)
      [[ "$code" == "200" ]] && printf '%s\tGCS\tPUBLIC-LISTABLE (200)\n' "$url" >> "$OUT/buckets.txt"
      # Azure Blob
      url="https://${name}.blob.core.windows.net/"
      code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' "$url" 2>/dev/null || echo 000)
      [[ "$code" =~ ^(200|400|409)$ ]] && printf '%s\tAzure\tEXISTS (%s)\n' "$url" "$code" >> "$OUT/buckets.txt"
    done
  done
  if [[ -s "$OUT/buckets.txt" ]]; then
    sort -u -o "$OUT/buckets.txt" "$OUT/buckets.txt"
    grep -q 'PUBLIC-LISTABLE' "$OUT/buckets.txt" && warn "PUBLIC-LISTABLE cloud bucket(s) found -> $OUT/buckets.txt" \
      || ok "Cloud bucket candidates (existence only) -> $OUT/buckets.txt"
  else
    ok "No matching cloud buckets discovered."
  fi
}

# ---- Sub-task: exposed source repositories --------------------------------
# Phase 04 already probed /.git/HEAD per web root; consolidate any hits here
# and confirm the repo is actually browsable.
t_exposed_git() {
  : > "$OUT/exposed_git.txt"
  local EXP="$RUN/04-web/exposures.txt"
  if [[ -s "$EXP" ]]; then
    grep -iE '/\.git/|/\.svn/|/\.env|\.git-credentials' "$EXP" 2>/dev/null | sort -u >> "$OUT/exposed_git.txt" || true
  fi
  [[ -s "$OUT/exposed_git.txt" ]] && warn "Exposed VCS/secret files -> $OUT/exposed_git.txt" \
    || log "No exposed .git/.svn/.env from the web phase."
}

task dangling     "Dangling-CNAME enumeration (3rd-party services)"  t_dangling
task takeover     "Subdomain-takeover scan (subzy/subjack/nuclei)"   t_takeover
task buckets      "Cloud storage bucket discovery (S3/GCS/Azure)"    t_buckets
task exposed_git  "Consolidate exposed .git/.svn/.env repos"         t_exposed_git
task ai           "AI: triage takeover / cloud exposure"             ai_bridge_06
run_tasks

ok "Takeover / cloud exposure review complete -> $OUT"
