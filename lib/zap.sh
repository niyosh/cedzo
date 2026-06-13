#!/usr/bin/env bash
# ==========================================================================
# lib/zap.sh  -  OWASP ZAP headless web scan (spider + passive + active).
#
# Sourced by lib/common.sh, so both web phases (04-enum-web.sh / x04-enum-web.sh)
# get zap_web_scan. ZAP is driven entirely from the CLI: we launch it in daemon
# mode bound to 127.0.0.1 and orchestrate it through its REST API with curl —
# no GUI, no jq, no docker. For each target web root we run:
#
#     1. accessUrl   — seed the site tree (passive scan starts automatically)
#     2. spider      — traditional crawl (+ optional AJAX spider)
#     3. passive     — wait for the passive-scan queue to drain
#     4. active      — ZAP active scan (OPT-IN; sends attack payloads)
#
# then export an HTML report + JSON alerts + a brief risk summary.
#
# NOTE ON SAFETY: the active scan sends real attack payloads (XSS/SQLi/etc.) and
# is therefore intrusive — it is gated behind ZAP_ACTIVE and should only be run
# with authorisation. Set ZAP_ACTIVE=false for spider+passive only (baseline).
# ==========================================================================

# Resolve a usable ZAP launcher (Kali ships `zaproxy`; the raw script is zap.sh).
ZAP_BIN=""
zap_runner() {
  [[ -n "$ZAP_BIN" ]] && { echo "$ZAP_BIN"; return 0; }
  if   have zap.sh;                       then ZAP_BIN="zap.sh"
  elif have zaproxy;                      then ZAP_BIN="zaproxy"
  elif [[ -x /usr/share/zaproxy/zap.sh ]]; then ZAP_BIN="/usr/share/zaproxy/zap.sh"
  else return 1; fi
  echo "$ZAP_BIN"
}

# Extract a single scalar field from a ZAP JSON reply on stdin (avoids a jq dep).
# e.g. {"scan":"3"} -> 3 ; {"status":"100"} -> 100 ; {"recordsToScan":"0"} -> 0
_zap_get() {
  grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"?[^\",}]+" | head -1 \
    | sed -E "s/.*:[[:space:]]*\"?//"
}

# Poll a ZAP "view/status" endpoint until it reaches 100 or a timeout (minutes).
_zap_wait_status() {  # <status-url> <timeout-minutes> <label>
  local surl="$1" mins="$2" label="$3" st="" i deadline
  deadline=$(( mins * 60 / 3 )); (( deadline < 1 )) && deadline=1
  for (( i=0; i<deadline; i++ )); do
    st=$(curl -s "$surl" 2>/dev/null | _zap_get status)
    [[ "$st" == "100" ]] && { ok "ZAP $label complete"; return 0; }
    sleep 3
  done
  warn "ZAP $label hit ${mins}m timeout (last ${st:-?}%) — moving on."
  return 0
}

# zap_web_scan <targets_file> <out_dir>
#   Scans up to ZAP_MAX_TARGETS web roots from <targets_file>. Degrades cleanly
#   (warn + return 0) if ZAP/curl is missing, there are no targets, or the
#   daemon never comes up — never aborts the calling phase.
zap_web_scan() {
  local targets="$1" odir="$2"
  [[ "${ZAP_SCAN:-true}" == "true" ]] || { warn "ZAP_SCAN=false — skipping ZAP web scan."; return 0; }

  local zb; zb=$(zap_runner) || { warn "OWASP ZAP not found (install zaproxy) — skipping ZAP scan."; return 0; }
  have curl || { warn "curl missing — skipping ZAP scan."; return 0; }
  [[ -s "$targets" ]] || { warn "No web targets for ZAP — skipping."; return 0; }
  mkdir -p "$odir"

  local port="${ZAP_PORT:-8090}" base="http://127.0.0.1:${ZAP_PORT:-8090}"
  local dlog="$odir/zap-daemon.log"

  log "Launching OWASP ZAP daemon ($zb) on 127.0.0.1:$port (headless)"
  "$zb" -daemon -host 127.0.0.1 -port "$port" \
    -config api.disablekey=true -config api.addr=127.0.0.1 \
    -config connection.timeoutInSecs=30 \
    > "$dlog" 2>&1 &
  local zpid=$!

  # Wait for the API to answer (cold start can take 20-40s; allow ~2 min).
  local ready="" i
  for i in $(seq 1 60); do
    kill -0 "$zpid" 2>/dev/null || { warn "ZAP daemon exited during startup — see $dlog."; return 0; }
    curl -s "$base/JSON/core/view/version/" 2>/dev/null | grep -q '"version"' && { ready=1; break; }
    sleep 2
  done
  [[ -n "$ready" ]] || {
    warn "ZAP API did not come up in time — skipping (see $dlog)."
    curl -s "$base/JSON/core/action/shutdown/" >/dev/null 2>&1
    kill "$zpid" 2>/dev/null; return 0
  }
  ok "ZAP API ready (pid $zpid)"
  [[ "${ZAP_ACTIVE:-true}" == "true" ]] \
    && warn "ZAP ACTIVE scan is ENABLED — it sends attack payloads. Set ZAP_ACTIVE=false for passive+spider only." \
    || log  "ZAP active scan disabled (ZAP_ACTIVE=false) — running spider + passive only."

  local max="${ZAP_MAX_TARGETS:-10}" n=0 url
  while read -r url; do
    [[ -n "$url" ]] || continue
    n=$(( n + 1 ))
    if (( n > max )); then
      warn "ZAP target cap ($max) reached — remaining roots skipped (raise ZAP_MAX_TARGETS)."
      break
    fi
    log "ZAP[$n/$max] $url — access + spider"
    curl -s -G "$base/JSON/core/action/accessUrl/" --data-urlencode "url=$url" >/dev/null 2>&1 || true

    # 2) Traditional spider.
    local sid; sid=$(curl -s -G "$base/JSON/spider/action/scan/" \
      --data-urlencode "url=$url" --data-urlencode "recurse=true" 2>/dev/null | _zap_get scan)
    [[ "$sid" =~ ^[0-9]+$ ]] && _zap_wait_status "$base/JSON/spider/view/status/?scanId=$sid" "${ZAP_SPIDER_TIMEOUT:-5}" "spider"

    # 2b) Optional AJAX spider (JS-heavy apps; needs a browser on the box).
    if [[ "${ZAP_AJAX_SPIDER:-false}" == "true" ]]; then
      log "ZAP[$n] AJAX spider"
      curl -s -G "$base/JSON/ajaxSpider/action/scan/" --data-urlencode "url=$url" >/dev/null 2>&1 || true
      local a="" j
      for (( j=0; j < ${ZAP_SPIDER_TIMEOUT:-5} * 20; j++ )); do
        a=$(curl -s "$base/JSON/ajaxSpider/view/status/" 2>/dev/null | _zap_get status)
        [[ "$a" == "stopped" ]] && break; sleep 3
      done
    fi

    # 3) Let the passive scanner drain its queue.
    log "ZAP[$n] waiting for passive scan queue to drain"
    local rec
    for (( j=0; j<150; j++ )); do
      rec=$(curl -s "$base/JSON/pscan/view/recordsToScan/" 2>/dev/null | _zap_get recordsToScan)
      [[ "${rec:-0}" == "0" ]] && break; sleep 2
    done

    # 4) Active scan (intrusive; opt-in).
    if [[ "${ZAP_ACTIVE:-true}" == "true" ]]; then
      log "ZAP[$n] active scan (attack payloads) on $url"
      local aid; aid=$(curl -s -G "$base/JSON/ascan/action/scan/" \
        --data-urlencode "url=$url" --data-urlencode "recurse=true" \
        --data-urlencode "inScopeOnly=false" 2>/dev/null | _zap_get scan)
      [[ "$aid" =~ ^[0-9]+$ ]] && _zap_wait_status "$base/JSON/ascan/view/status/?scanId=$aid" "${ZAP_ACTIVE_TIMEOUT:-20}" "active"
    fi
  done < "$targets"

  # ---- Reports -----------------------------------------------------------
  log "ZAP: exporting report + alerts"
  curl -s "$base/OTHER/core/other/htmlreport/" -o "$odir/zap_report.html" 2>/dev/null || true
  curl -s "$base/JSON/core/view/alerts/"        -o "$odir/zap_alerts.json" 2>/dev/null || true

  if [[ -s "$odir/zap_alerts.json" ]]; then
    local H M L I
    H=$(grep -oE '"risk":"High"'          "$odir/zap_alerts.json" | wc -l | tr -d ' ')
    M=$(grep -oE '"risk":"Medium"'        "$odir/zap_alerts.json" | wc -l | tr -d ' ')
    L=$(grep -oE '"risk":"Low"'           "$odir/zap_alerts.json" | wc -l | tr -d ' ')
    I=$(grep -oE '"risk":"Informational"' "$odir/zap_alerts.json" | wc -l | tr -d ' ')
    printf 'ZAP alerts — High:%s Medium:%s Low:%s Info:%s\n' "$H" "$M" "$L" "$I" > "$odir/zap_summary.txt"
    ok "ZAP report -> $odir/zap_report.html  (High:$H Medium:$M Low:$L Info:$I)"
  else
    warn "ZAP produced no alerts JSON (see $dlog)."
  fi

  # ---- Shutdown ----------------------------------------------------------
  curl -s "$base/JSON/core/action/shutdown/" >/dev/null 2>&1 || true
  sleep 2; kill "$zpid" 2>/dev/null || true
  return 0
}
