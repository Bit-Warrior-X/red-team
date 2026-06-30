#!/usr/bin/env bash
# ============================================================
#  PHASE 2 — TRAFFIC & PERFORMANCE VALIDATION
#  CDN IP  : 172.105.75.48
#  Domains : www.linhu110.com | www.lkiuouqijgkdhcnxshh.xyz
#  Requires: wrk, ab (apache2-utils), hey (optional)
# ============================================================
set -uo pipefail

CDN_IP="${CDN_IP:-172.105.75.48}"
CDN_PORT="${CDN_PORT:-80}"
CDN_HTTPS_PORT="${CDN_HTTPS_PORT:-443}"
HOST_HEADER="${HOST_HEADER:-www.linhu110.com}"
DOMAINS=("www.linhu110.com" "www.lkiuouqijgkdhcnxshh.xyz")
CONCURRENCY="${CONCURRENCY:-50}"
REQUESTS="${REQUESTS:-5000}"
DURATION="${DURATION:-30}"
NGINX_PREFIX="/usr/local/openresty/nginx"
LOG="$NGINX_PREFIX/logs/access.log"
REPORT_DIR="/var/log/cdn-tests/perf-$(date +%Y%m%d_%H%M%S)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31d'; NC='\033[0m'; BOLD='\033[1m'
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "\n${BOLD}── $1 ──${NC}"; }

mkdir -p "$REPORT_DIR"
HTTP_TARGET="http://$CDN_IP:$CDN_PORT/"
HTTPS_TARGET="https://$CDN_IP:$CDN_HTTPS_PORT/"

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  PHASE 2: TRAFFIC & PERFORMANCE        ${NC}"
echo -e "${BOLD}  CDN    : $CDN_IP                      ${NC}"
echo -e "${BOLD}  Host   : $HOST_HEADER                 ${NC}"
echo -e "${BOLD}  c=$CONCURRENCY  n=$REQUESTS  t=${DURATION}s  ${NC}"
echo -e "${BOLD}  $(date '+%Y-%m-%d %H:%M:%S')          ${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

# ── P1: TOOL CHECK ───────────────────────────────────────────
info "P1: Available benchmark tools"
HAS_AB=false; HAS_WRK=false; HAS_HEY=false
command -v ab  &>/dev/null && { HAS_AB=true;  pass "ab found  ($(ab -V 2>&1 | head -1))"; } || \
  warn "ab not found — install: apt-get install apache2-utils"
command -v wrk &>/dev/null && { HAS_WRK=true; pass "wrk found"; }                            || \
  warn "wrk not found — install: apt-get install wrk"
command -v hey &>/dev/null && { HAS_HEY=true; pass "hey found"; }                            || \
  warn "hey not found — go install github.com/rakyll/hey@latest"

# ── P2: PRE-TEST BASELINE ────────────────────────────────────
info "P2: Pre-test stub_status snapshot"
curl -s --unix-socket /var/run/nginx.sock http://localhost/nginx-status \
  | tee "$REPORT_DIR/prestub.txt"
PRE_ACTIVE=$(curl -s --unix-socket /var/run/nginx.sock http://localhost/nginx-status | \
  grep "Active connections" | awk '{print $3}')
echo "  Pre-test active connections: $PRE_ACTIVE"

# ── P3: SINGLE REQUEST LATENCY ───────────────────────────────
info "P3: Single-request latency baseline (HTTP + HTTPS)"
echo "  HTTP:"
for i in 1 2 3; do
  curl -s -o /dev/null \
    -w "    Req $i → connect:%{time_connect}s  ttfb:%{time_starttransfer}s  total:%{time_total}s  HTTP:%{http_code}\n" \
    "$HTTP_TARGET" -H "Host: $HOST_HEADER"
done | tee "$REPORT_DIR/latency_single_http.txt"
echo "  HTTPS:"
for i in 1 2 3; do
  curl -sk -o /dev/null \
    -w "    Req $i → connect:%{time_connect}s  ttfb:%{time_starttransfer}s  total:%{time_total}s  HTTP:%{http_code}\n" \
    "$HTTPS_TARGET" -H "Host: $HOST_HEADER"
done | tee "$REPORT_DIR/latency_single_https.txt"

# ── P4: AB — HTTP THROUGHPUT ─────────────────────────────────
info "P4: ab — HTTP throughput (n=$REQUESTS, c=$CONCURRENCY)"
if $HAS_AB; then
  ab -n "$REQUESTS" -c "$CONCURRENCY" \
     -H "Host: $HOST_HEADER" \
     -H "Accept-Encoding: identity" \
     "$HTTP_TARGET" 2>&1 | tee "$REPORT_DIR/ab_http.txt"
  RPS=$(grep "Requests per second" "$REPORT_DIR/ab_http.txt" | awk '{print $4}')
  P99=$(grep "99%"                 "$REPORT_DIR/ab_http.txt" | awk '{print $2}')
  FAIL_AB=$(grep "Failed requests" "$REPORT_DIR/ab_http.txt" | awk '{print $3}')
  echo ""
  echo "  HTTP Results:"
  echo "    RPS         : $RPS req/s"
  echo "    p99 latency : ${P99}ms"
  echo "    Failed reqs : $FAIL_AB"
  [ "${FAIL_AB:-1}" -eq 0 ] && pass "Zero failed requests (HTTP ab)" || fail "Failed requests: $FAIL_AB"
  RPS_INT=$(echo "${RPS:-0}" | cut -d. -f1)
  [ "${RPS_INT:-0}" -gt 500 ] && pass "RPS > 500 ($RPS)" || warn "Low RPS: $RPS — check upstream"
else
  warn "Skipping ab HTTP test (not installed)"
fi

# ── P5: AB — HTTPS THROUGHPUT ────────────────────────────────
info "P5: ab — HTTPS throughput (n=$REQUESTS, c=$CONCURRENCY)"
if $HAS_AB; then
  ab -n "$REQUESTS" -c "$CONCURRENCY" \
     -H "Host: $HOST_HEADER" \
     -H "Accept-Encoding: identity" \
     -f TLS1.2 \
     "${HTTPS_TARGET}" 2>&1 | tee "$REPORT_DIR/ab_https.txt" || \
       warn "ab HTTPS failed — may need -k flag or cert validation issue"
  HTTPS_RPS=$(grep "Requests per second" "$REPORT_DIR/ab_https.txt" 2>/dev/null | awk '{print $4}' || echo "N/A")
  HTTPS_FAIL=$(grep "Failed requests" "$REPORT_DIR/ab_https.txt" 2>/dev/null | awk '{print $3}' || echo "N/A")
  echo "    HTTPS RPS    : $HTTPS_RPS"
  echo "    HTTPS Fails  : $HTTPS_FAIL"
  [ "${HTTPS_FAIL:-1}" = "0" ] && pass "Zero failed HTTPS requests" || warn "HTTPS failed requests: $HTTPS_FAIL"
else
  warn "Skipping ab HTTPS test (not installed)"
fi

# ── P6: WRK — HTTP SUSTAINED LOAD ────────────────────────────
info "P6: wrk — HTTP sustained load (${DURATION}s, c=$CONCURRENCY)"
if $HAS_WRK; then
  wrk -t4 -c"$CONCURRENCY" -d"${DURATION}s" \
      -H "Host: $HOST_HEADER" \
      --latency \
      "$HTTP_TARGET" 2>&1 | tee "$REPORT_DIR/wrk_http.txt"
  WRK_ERR=$(grep "Socket errors" "$REPORT_DIR/wrk_http.txt" || echo "")
  [ -z "$WRK_ERR" ] && pass "No socket errors (HTTP wrk)" || warn "Socket errors: $WRK_ERR"
else
  warn "Skipping wrk HTTP test (not installed)"
fi

# ── P7: WRK — HTTPS SUSTAINED LOAD ──────────────────────────
info "P7: wrk — HTTPS sustained load (${DURATION}s, c=$CONCURRENCY)"
if $HAS_WRK; then
  wrk -t4 -c"$CONCURRENCY" -d"${DURATION}s" \
      -H "Host: $HOST_HEADER" \
      --latency \
      "$HTTPS_TARGET" 2>&1 | tee "$REPORT_DIR/wrk_https.txt" || \
        warn "wrk HTTPS failed — check TLS on $CDN_IP:$CDN_HTTPS_PORT"
  WRK_HTTPS_ERR=$(grep "Socket errors" "$REPORT_DIR/wrk_https.txt" 2>/dev/null || echo "")
  [ -z "$WRK_HTTPS_ERR" ] && pass "No socket errors (HTTPS wrk)" || warn "HTTPS socket errors: $WRK_HTTPS_ERR"
else
  warn "Skipping wrk HTTPS test (not installed)"
fi

# ── P8: CONCURRENCY SPIKE ────────────────────────────────────
info "P8: wrk — concurrency spike (c=500, ${DURATION}s)"
if $HAS_WRK; then
  wrk -t8 -c500 -d"${DURATION}s" \
      -H "Host: $HOST_HEADER" \
      --latency \
      "$HTTP_TARGET" 2>&1 | tee "$REPORT_DIR/wrk_spike.txt"
  pass "Spike test complete — check p99 above"
else
  warn "Skipping spike test (wrk not installed)"
fi

# ── P9: HEY — PERCENTILE DISTRIBUTION ───────────────────────
info "P9: hey — latency percentile distribution"
if $HAS_HEY; then
  hey -n "$REQUESTS" -c "$CONCURRENCY" \
      -H "Host: $HOST_HEADER" \
      -m GET \
      "$HTTP_TARGET" 2>&1 | tee "$REPORT_DIR/hey_http.txt"
  pass "hey percentiles saved"
else
  warn "Skipping hey (not installed)"
fi

# ── P10: MULTI-DOMAIN CONCURRENCY ────────────────────────────
info "P10: Multi-domain concurrent requests (both domains)"
if $HAS_WRK; then
  for domain in "${DOMAINS[@]}"; do
    echo "  Testing: $domain"
    wrk -t2 -c20 -d10s -H "Host: $domain" "$HTTP_TARGET" 2>&1 | \
      grep -E "Requests/sec|Latency" | tee -a "$REPORT_DIR/wrk_multidomain.txt"
  done
  pass "Multi-domain test complete"
else
  for domain in "${DOMAINS[@]}"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HTTP_TARGET" -H "Host: $domain")
    echo "  $domain → HTTP $CODE"
  done
  pass "Multi-domain spot check done"
fi

# ── P11: WORKER CONNECTION SATURATION ────────────────────────
info "P11: Worker connection saturation check"
POST_ACTIVE=$(curl -s --unix-socket /var/run/nginx.sock http://localhost/nginx-status | \
  grep "Active connections" | awk '{print $3}')
WORKER_COUNT=$(ps aux | grep "nginx: worker" | grep -v grep | wc -l)
MAX_CONNS=$((51200 * WORKER_COUNT))
THRESHOLD=$(( MAX_CONNS * 70 / 100 ))
echo "  Active connections : $POST_ACTIVE"
echo "  Worker count       : $WORKER_COUNT"
echo "  Max capacity       : $MAX_CONNS  (70% threshold: $THRESHOLD)"
[ "${POST_ACTIVE:-0}" -lt "$THRESHOLD" ] && \
  pass "Connection utilization OK ($POST_ACTIVE active, threshold $THRESHOLD)" || \
  warn "High connection count: $POST_ACTIVE — approaching limit"
curl -s --unix-socket /var/run/nginx.sock http://localhost/nginx-status \
  | tee "$REPORT_DIR/poststub.txt"

# ── P12: CACHE HIT RATIO ─────────────────────────────────────
info "P12: Cache HIT ratio from access log (last 2000 lines)"
# upstream_cache_status is field 17 (quoted) in your log format:
# $remote_addr $site_id "$site_name" $host [$time] $method $uri $proto
# $status $bytes "$referer" "$ua" "$xff" $scheme $req_time $upstream_addr
# "$upstream_cache_status" <literal_ip> $block_type:$block_cause ...
if [ -f "$LOG" ]; then
  echo "  Upstream cache status distribution (field 17):"
  tail -2000 "$LOG" | awk '{gsub(/"/, "", $17); print $17}' | \
    sort | uniq -c | sort -rn | \
    while read count status; do
      printf "    %-12s : %s\n" "$status" "$count"
    done | tee "$REPORT_DIR/cache_ratio.txt"
  HIT_COUNT=$(tail -2000 "$LOG" | awk '{gsub(/"/, "", $17); print $17}' | grep -c "^HIT$" || true)
  HIT_COUNT="${HIT_COUNT:-0}"
  TOTAL=$(tail -2000 "$LOG" | wc -l | tr -d ' ')
  if [ "$TOTAL" -gt 0 ] && [ "$HIT_COUNT" -ge 0 ] 2>/dev/null; then
    HIT_PCT=$(awk "BEGIN {printf \"%.1f\", $HIT_COUNT * 100 / $TOTAL}")
    echo "  HIT ratio: $HIT_PCT% ($HIT_COUNT/$TOTAL)"
    [ "$HIT_COUNT" -gt 0 ] && pass "Cache HITs present (${HIT_PCT}%)" || \
      warn "No cache HITs yet — normal for cold cache or when cache_zone=off per site config"
  fi
else
  warn "Access log not found: $LOG"
fi

# ── P13: UPSTREAM RESPONSE TIMES ─────────────────────────────
info "P13: Upstream response time analysis (last 2000 log lines)"
# upstream_response_time is field 20 in your log format
if [ -f "$LOG" ]; then
  echo "  Slowest 10 upstream_response_times (field 20):"
  tail -2000 "$LOG" | awk '{gsub(/"/, "", $20); if($20 ~ /^[0-9]/) print $20}' | \
    sort -n | tail -10 | sed 's/^/    /'
  AVG=$(tail -2000 "$LOG" | awk '{gsub(/"/, "", $20); if($20 ~ /^[0-9]/) {sum+=$20; count++}} \
    END {if(count>0) printf "%.3f", sum/count; else print "N/A"}')
  echo "  Avg upstream response time: ${AVG}s"
  pass "Upstream response time analysis done"
fi

# ── P14: MEMORY AFTER LOAD ───────────────────────────────────
info "P14: Memory usage after load test"
ps aux | grep openresty | grep -v grep | \
  awk '{sum+=$6} END {printf "  Total RSS after load: %.1f MB\n", sum/1024}' \
  | tee "$REPORT_DIR/post_memory.txt"
pass "Memory snapshot saved"

# ── P15: ERROR LOG DELTA ─────────────────────────────────────
info "P15: Error log — new entries since load test"
NEW_ERRORS=$(tail -200 "$NGINX_PREFIX/logs/error.log" 2>/dev/null | \
  grep "\[error\]" | grep -v "event worker failed to communicate with broker" | wc -l | tr -d ' ')
NEW_CRITS=$(tail -200 "$NGINX_PREFIX/logs/error.log" 2>/dev/null | \
  grep "\[crit\]" | wc -l | tr -d ' ')
NEW_ERRORS="${NEW_ERRORS:-0}"; NEW_CRITS="${NEW_CRITS:-0}"
echo "  Real [error] in last 200 lines: $NEW_ERRORS"
echo "  [crit]  in last 200 lines: $NEW_CRITS"
[ "$NEW_ERRORS" -eq 0 ] && pass "No errors during load" || warn "$NEW_ERRORS error(s) — review error.log"
[ "$NEW_CRITS"  -eq 0 ] && pass "No critical errors"    || fail "$NEW_CRITS critical error(s)"

echo ""
echo -e "${BOLD}════════════════════════════════════════${NC}"
echo -e "${BOLD}  PHASE 2: PERFORMANCE TEST COMPLETE${NC}"
echo -e "${BOLD}  Reports saved to: $REPORT_DIR${NC}"
echo -e "${BOLD}════════════════════════════════════════${NC}"
echo ""
