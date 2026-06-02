#!/usr/bin/env bash
# ==========================================================================
# 04-enum-web.sh  -  Probe, fingerprint, screenshot, content-discover, scan
# all HTTP/S services found in the port scan.
# ==========================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
source ./lib/common.sh
RUN="${RUN:?RUN not set}"
OUT="$RUN/04-web"; mkdir -p "$OUT"; LOG="$OUT/web.log"
URLS="$RUN/web_urls.txt"
[[ -s "$URLS" ]] || { warn "No web URLs (run 02 first). Skipping."; exit 0; }

phase "Web Enumeration ($(wc -l <"$URLS") targets)"

# ---- Probe + fingerprint --------------------------------------------------
if have httpx; then
  log "httpx: live check, titles, tech, status, redirects"
  run "$LOG" httpx -silent -l "$URLS" \
    -title -tech-detect -status-code -server -web-server -location -ip \
    -o "$OUT/httpx.txt" || true
  # keep only live URLs for the heavier steps
  httpx -silent -l "$URLS" -o "$OUT/live_urls.txt" 2>/dev/null || cp "$URLS" "$OUT/live_urls.txt"
else
  cp "$URLS" "$OUT/live_urls.txt"
fi
LIVE_URLS="$OUT/live_urls.txt"

if have whatweb; then
  log "whatweb fingerprint (aggression 3)"
  run "$LOG" whatweb -a3 --no-errors -i "$LIVE_URLS" \
    --log-brief="$OUT/whatweb.txt" || true
fi

# ---- Screenshots ----------------------------------------------------------
if [[ "$SCREENSHOTS" == "true" ]] && have gowitness; then
  log "gowitness screenshots"
  if gowitness scan --help >/dev/null 2>&1; then
    run "$LOG" gowitness scan file -f "$LIVE_URLS" \
      --write-db --screenshot-path "$OUT/screens" 2>/dev/null || true
  else
    run "$LOG" gowitness file -f "$LIVE_URLS" -P "$OUT/screens" 2>/dev/null || true
  fi
  ok "Screenshots -> $OUT/screens"
fi

# ---- Crawl + content discovery (katana + dirsearch) -----------------------
# Crawl live web roots and brute-force common paths, then merge + prioritise
# into a clean endpoint list that enriches the nuclei target set.
NUCLEI_TARGETS="$LIVE_URLS"
if [[ "${WEB_CRAWL:-true}" == "true" ]]; then
  KATANA_OUT="$OUT/katana.txt"; DIRS_OUT="$OUT/dirsearch.txt"
  if have katana; then
    log "katana crawl (JS-aware, depth ${KATANA_DEPTH:-2})"
    run "$LOG" katana -list "$LIVE_URLS" -jc -d "${KATANA_DEPTH:-2}" -silent \
      -o "$KATANA_OUT" 2>/dev/null || true
  fi
  if have dirsearch; then
    log "dirsearch content discovery"
    run "$LOG" dirsearch -l "$LIVE_URLS" --format plain -o "$DIRS_OUT" 2>/dev/null || true
  fi
  # Merge + prioritise crawled/brute-forced URLs (good codes, params, dynamic).
  if have python3 && { [[ -s "$KATANA_OUT" ]] || [[ -s "$DIRS_OUT" ]]; }; then
    python3 reporting/urlfilter.py "$KATANA_OUT" "$DIRS_OUT" \
      -o "$OUT/filtered_urls.txt" 2>/dev/null || true
    if [[ -s "$OUT/filtered_urls.txt" ]]; then
      sort -u "$LIVE_URLS" "$OUT/filtered_urls.txt" > "$OUT/nuclei_targets.txt"
      NUCLEI_TARGETS="$OUT/nuclei_targets.txt"
      ok "Enriched nuclei targets: $(wc -l <"$NUCLEI_TARGETS") (roots + discovered)"
    fi
  fi
fi

# ---- Vuln scan ------------------------------------------------------------
if have nuclei; then
  log "nuclei (auto templates, info+low+med+high+critical)"
  run "$LOG" nuclei -l "$NUCLEI_TARGETS" -severity info,low,medium,high,critical \
    -rl 150 -c 25 -o "$OUT/nuclei.txt" -stats 2>/dev/null || true
  ok "nuclei findings: $( [[ -f "$OUT/nuclei.txt" ]] && wc -l <"$OUT/nuclei.txt" || echo 0 )"
fi

# ---- Content discovery (per host, capped concurrency) ---------------------
if have feroxbuster && [[ -s "$WEB_WORDLIST" ]]; then
  ferox_one() {
    local url="$1"
    local safe; safe=$(sed 's#[^A-Za-z0-9]#_#g' <<<"$url")
    feroxbuster -u "$url" -w "$WEB_WORDLIST" -q -k -t 20 \
      -x php,asp,aspx,jsp,html,txt,bak,config \
      --no-recursion -o "$OUT/ferox_$safe.txt" 2>/dev/null || true
    printf '%s[+]%s dirbust %s\n' "$C_GRN" "$C_RST" "$url"
  }
  export -f ferox_one; export OUT WEB_WORDLIST C_GRN C_RST
  log "feroxbuster content discovery (parallel, capped)"
  THREADS_WEB=$(( THREADS<6 ? THREADS : 6 ))   # don't hammer
  xargs -P "$THREADS_WEB" -I{} bash -c 'ferox_one "$@"' _ {} < "$LIVE_URLS"
fi
ok "Web enumeration complete -> $OUT"
