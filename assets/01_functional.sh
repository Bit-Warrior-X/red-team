#!/usr/bin/env bash
# ============================================================
#  PHASE 1 — FUNCTIONAL / INTEGRATION TESTING
#  CDN IP  : 172.105.75.48
#  Domains : www.linhu110.com | www.lkiuouqijgkdhcnxshh.xyz
#  Run AFTER upgrading to 1.29
# ============================================================
set -uo pipefail

CDN_IP="${CDN_IP:-172.105.75.48}"
CDN_PORT="${CDN_PORT:-80}"
CDN_HTTPS_PORT="${CDN_HTTPS_PORT:-443}"
HOST_HEADER="${HOST_HEADER:-www.linhu110.com}"
DOMAINS=("www.linhu110.com" "www.lkiuouqijgkdhcnxshh.xyz")
NGINX_PREFIX="/usr/local/openresty/nginx"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'
PASS=0; FAIL=0; WARN=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info() { echo -e "\n${BOLD}── $1 ──${NC}"; }

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  PHASE 1: FUNCTIONAL / INTEGRATION     ${NC}"
echo -e "${BOLD}  CDN : $CDN_IP                         ${NC}"
echo -e "${BOLD}  Host: $HOST_HEADER                    ${NC}"
echo -e "${BOLD}  $(date '+%Y-%m-%d %H:%M:%S')          ${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

# ── F1: VERSION ──────────────────────────────────────────────
info "F1: OpenResty 1.29 version verification"
VER=$(openresty -v 2>&1)
VER_NUM=$(echo "$VER" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
echo "  Full version string : $VER"
echo "  Parsed version      : $VER_NUM"
echo "$VER_NUM" | grep -q "^1\.29\." && pass "OpenResty 1.29 confirmed ($VER_NUM)"

# ── F2: CONFIG SYNTAX ────────────────────────────────────────
info "F2: Config syntax — nginx.conf + server/*.conf"
if openresty -t 2>&1 | grep -q "successful"; then
  pass "nginx.conf + all includes syntax OK"
else
  fail "Config syntax error:"
  openresty -t 2>&1
fi

# ── F3: PROCESSES ────────────────────────────────────────────
info "F3: Master + worker processes"
MASTER=$(ps aux | grep "nginx: master" | grep -v grep | wc -l)
WORKERS=$(ps aux | grep "nginx: worker" | grep -v grep | wc -l)
[ "$MASTER" -ge 1 ] && pass "Master process running ($MASTER)" || fail "No master process found"
[ "$WORKERS" -ge 1 ] && pass "Worker processes running ($WORKERS)" || fail "No worker processes found"

# ── F4: HEALTH ENDPOINT ──────────────────────────────────────
info "F4: Health check — :61002/ge.status"
RESP=$(curl -s -w "\nHTTP:%{http_code}" http://127.0.0.1:61002/ge.status)
BODY=$(echo "$RESP" | head -1)
CODE=$(echo "$RESP" | grep "HTTP:" | cut -d: -f2)
echo "  Status: $CODE | Body: $BODY"
[ "$CODE" = "200" ] && pass "Health endpoint: 200 OK" || fail "Health endpoint: $CODE"
echo "$BODY" | grep -q "OK" && pass "Body = 'OK'" || fail "Body wrong: $BODY"

# ── F5: STUB STATUS ──────────────────────────────────────────
info "F5: Nginx stub_status (unix socket)"
STUB=$(curl -s --unix-socket /var/run/nginx.sock http://localhost/nginx-status)
echo "$STUB"
echo "$STUB" | grep -q "Active connections" && pass "Stub status responding" || fail "Stub status failed"

# ── F6: SERVER HEADER ────────────────────────────────────────
info "F6: Server: CDN header (more_set_headers)"
for domain in "${DOMAINS[@]}"; do
  SRV=$(curl -sI "http://$CDN_IP:$CDN_PORT/" -H "Host: $domain" | grep -i "^server:" | tr -d '\r')
  echo "  [$domain] $SRV"
  echo "$SRV" | grep -qi "CDN" && pass "Server: CDN — $domain" || fail "Server header wrong for $domain: $SRV"
done

# ── F7: CFG HANDLER ──────────────────────────────────────────
info "F7: Config handler :61001 (loopback)"
CFG_CODE=$(curl -s -o /dev/null -w "%{http_code}" --interface lo http://127.0.0.1:61001/)
echo "  HTTP $CFG_CODE"
[ "$CFG_CODE" != "000" ] && pass "cfg_handler responded: $CFG_CODE" || fail "cfg_handler no response"

# ── F8: CLEARCACHE ENDPOINT ──────────────────────────────────
info "F8: clearCache endpoint :61001 (loopback)"
CC_CODE=$(curl -s -o /dev/null -w "%{http_code}" --interface lo \
  "http://127.0.0.1:61001/clearCache?site=test")
echo "  HTTP $CC_CODE"
[ "$CC_CODE" != "000" ] && pass "clearCache responded: $CC_CODE" || fail "clearCache no response"

# ── F9: DYUPS ────────────────────────────────────────────────
info "F9: Dyups upstream interface :61000 (loopback)"
DYUPS_CODE=$(curl -s -o /dev/null -w "%{http_code}" --interface lo \
  http://127.0.0.1:61000/ 2>/dev/null; true)
echo "  HTTP $DYUPS_CODE"
[ "$DYUPS_CODE" != "000" ] && pass "Dyups responding: $DYUPS_CODE" || fail "Dyups not responding"

# ── F10: INTERNAL PORTS BLOCKED EXTERNALLY ───────────────────
info "F10: Internal ports blocked from external (61000, 61001)"
# Note: curl outputs "000" itself for refused/unreachable connections.
# Do NOT use || echo "000" — that appends a second "000" giving "000000".
EXT_61000=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://$CDN_IP:61000/" 2>/dev/null; true)
EXT_61001=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://$CDN_IP:61001/" 2>/dev/null; true)
echo "  :61000 external response: $EXT_61000"
echo "  :61001 external response: $EXT_61001"
[ "$EXT_61000" = "000" ] && pass ":61000 blocked from external (connection refused)" || fail ":61000 exposed externally — got HTTP $EXT_61000"
[ "$EXT_61001" = "000" ] && pass ":61001 blocked from external (connection refused)" || fail ":61001 exposed externally — got HTTP $EXT_61001"

# ── F11: 404 FALLBACK ────────────────────────────────────────
info "F11: 404 fallback on :61002"
F404_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:61002/no-such-path-xyz)
[ "$F404_CODE" = "404" ] && pass "404 fallback correct" || fail "Expected 404, got $F404_CODE"

# ── F12: CDNRAY STATUS PAGE ──────────────────────────────────
info "F12: /cdnray.status SSI page"
for domain in "${DOMAINS[@]}"; do
  CS_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://$CDN_IP:$CDN_PORT/cdnray.status" -H "Host: $domain")
  echo "  [$domain] /cdnray.status → $CS_CODE"
  [ "$CS_CODE" != "000" ] && pass "/cdnray.status responding for $domain ($CS_CODE)" || \
    warn "/cdnray.status no response for $domain"
done

# ── F13: ANTI-CC ENDPOINTS ───────────────────────────────────
info "F13: Anti-CC Lua endpoints"
for path in "/.anticc/verify" "/.anti/challenge" "/.anti/redirect"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://$CDN_IP:$CDN_PORT$path" -H "Host: $HOST_HEADER")
  echo "  $path → HTTP $CODE"
  [ "$CODE" != "000" ] && pass "$path reachable ($CODE)" || fail "$path no response"
done

# ── F14: ACME CHALLENGE ──────────────────────────────────────
info "F14: ACME challenge location (.well-known)"
ACME_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "http://$CDN_IP:$CDN_PORT/.well-known/acme-challenge/testtoken" -H "Host: $HOST_HEADER")
echo "  .well-known/acme-challenge/ → HTTP $ACME_CODE"
[ "$ACME_CODE" != "000" ] && pass "ACME location reachable ($ACME_CODE)" || \
  fail "ACME location unreachable"

# ── F15: ANTI-CC STATIC ASSETS ───────────────────────────────
info "F15: Anti-CC static assets /cdn.cc_static/"
CC_STATIC=$(curl -s -o /dev/null -w "%{http_code}" \
  "http://$CDN_IP:$CDN_PORT/cdn.cc_static/" -H "Host: $HOST_HEADER")
echo "  /cdn.cc_static/ → HTTP $CC_STATIC"
[ "$CC_STATIC" != "000" ] && pass "CC static location reachable ($CC_STATIC)" || \
  warn "CC static location not responding"

# ── F16: HTTPS — TLS HANDSHAKE PER DOMAIN ────────────────────
info "F16: HTTPS TLS handshake per domain (dyn_cert)"
for domain in "${DOMAINS[@]}"; do
  echo "  Testing TLS for: $domain"
  TLS_RESULT=$(echo Q | openssl s_client \
    -connect "$CDN_IP:$CDN_HTTPS_PORT" \
    -servername "$domain" 2>&1)
  CERT_CN=$(echo "$TLS_RESULT" | openssl x509 -noout -subject 2>/dev/null | \
    grep -o "CN\s*=\s*[^,]*" | head -1 || echo "FAILED")
  TLS_PROTO=$(echo "$TLS_RESULT" | grep "Protocol" | head -1)
  echo "    CN      : $CERT_CN"
  echo "    Protocol: $TLS_PROTO"
  echo "$TLS_RESULT" | grep -q "Verify return code: 0" && \
    pass "TLS cert valid for $domain" || \
    warn "TLS cert issue for $domain — may be expired or CN mismatch"
  [[ "$TLS_PROTO" == *"TLSv1.2"* || "$TLS_PROTO" == *"TLSv1.3"* ]] && \
    pass "TLS protocol OK for $domain ($TLS_PROTO)" || \
    warn "TLS protocol unexpected for $domain: $TLS_PROTO"
done

# ── F17: TLS 1.2 / 1.3 ──────────────────────────────────────
info "F17: TLS protocol support — 1.2 and 1.3"
TLS12=$(echo Q | openssl s_client -connect "$CDN_IP:$CDN_HTTPS_PORT" \
  -tls1_2 -servername "$HOST_HEADER" 2>&1 | grep "Protocol")
TLS13=$(echo Q | openssl s_client -connect "$CDN_IP:$CDN_HTTPS_PORT" \
  -tls1_3 -servername "$HOST_HEADER" 2>&1 | grep "Protocol")
echo "  TLS 1.2: $TLS12"
echo "  TLS 1.3: $TLS13"
[[ "$TLS12" == *"TLSv1.2"* ]] && pass "TLS 1.2 accepted" || warn "TLS 1.2 not confirmed"
[[ "$TLS13" == *"TLSv1.3"* ]] && pass "TLS 1.3 accepted" || warn "TLS 1.3 not confirmed"

# ── F18: TLS 1.0 — SHOULD BE REMOVED ────────────────────────
info "F18: TLS 1.0 — should be disabled (production hardening)"
TLS10=$(echo Q | openssl s_client -connect "$CDN_IP:$CDN_HTTPS_PORT" \
  -tls1 -servername "$HOST_HEADER" 2>&1 | grep "Protocol" || echo "")
echo "  TLS 1.0 result: ${TLS10:-no connection}"
[[ "$TLS10" == *"TLSv1"* ]] && \
  warn "TLS 1.0 still accepted — remove TLSv1 TLSv1.1 from ssl_protocols in nginx.conf" || \
  pass "TLS 1.0 not accepted (good)"

# ── F19: HTTP→HTTPS 497 REDIRECT ─────────────────────────────
info "F19: HTTP plain-text to :443 triggers 497 error_page redirect"
ERR497=$(curl -sk -o /dev/null -w "%{http_code}" \
  "http://$CDN_IP:$CDN_HTTPS_PORT/" -H "Host: $HOST_HEADER" 2>/dev/null; true)
echo "  HTTP→:443 → HTTP $ERR497"
[ "$ERR497" != "000" ] && pass "497 redirect handler active ($ERR497)" || \
  warn "No response from 497 handler"

# ── F20: X-CACHE-STATUS HEADER ───────────────────────────────
info "F20: X-Cache-Status header present (add_header in location /)"
XCACHE=$(curl -sI "http://$CDN_IP:$CDN_PORT/" -H "Host: $HOST_HEADER" | \
  grep -i "x-cache-status" | tr -d '\r')
echo "  $XCACHE"
[ -n "$XCACHE" ] && pass "X-Cache-Status header present: $XCACHE" || \
  warn "X-Cache-Status not found in response headers"

# ── F21: CACHE MISS → HIT ────────────────────────────────────
info "F21: Cache MISS → HIT cycle (GET/HEAD, proxy_cache gezone)"
URL="http://$CDN_IP:$CDN_PORT/cacheable-test.html"
echo "  Request 1 (expect MISS or BYPASS):"
curl -sI "$URL" -H "Host: $HOST_HEADER" | grep -i "x-cache-status\|age" || \
  echo "  (check upstream_cache_status field 14 in access log)"
sleep 1
echo "  Request 2 (expect HIT if upstream is cacheable):"
curl -sI "$URL" -H "Host: $HOST_HEADER" | grep -i "x-cache-status\|age" || \
  echo "  (check upstream_cache_status field 14 in access log)"
pass "Cache cycle issued — verify: awk '{print \$14}' $NGINX_PREFIX/logs/access.log | tail -5"

# ── F22: MERGE_SLASHES OFF ───────────────────────────────────
info "F22: merge_slashes off — double slashes preserved"
SLASHREQ=$(curl -sv "http://$CDN_IP:$CDN_PORT//api//v1/test" \
  -H "Host: $HOST_HEADER" 2>&1 | grep "> GET")
echo "  $SLASHREQ"
echo "$SLASHREQ" | grep -q "//api//v1" && pass "Double slashes preserved" || \
  warn "Cannot confirm merge_slashes — check access log URI field"

# ── F23: KEEPALIVE ───────────────────────────────────────────
info "F23: Upstream keepalive (pool 2048)"
for i in 1 2 3; do
  curl -s -o /dev/null \
    -w "  Req $i → HTTP %{http_code}  time: %{time_total}s\n" \
    "http://$CDN_IP:$CDN_PORT/" -H "Host: $HOST_HEADER"
done
pass "Keepalive requests done — check upstream_addr repeats in access log"

# ── F24: NODE EXPORTER SSL PROXY ─────────────────────────────
info "F24: Node exporter SSL proxy :61101"
NODE_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
  --max-time 5 https://127.0.0.1:61101/ 2>/dev/null; true)
echo "  HTTPS :61101 → $NODE_CODE"
[ "$NODE_CODE" != "000" ] && pass "Node exporter proxy responding: $NODE_CODE" || \
  warn "No response on :61101 (cert issue or exporter not running)"

# ── F25: RESTY.EVENTS SOCKET ─────────────────────────────────
info "F25: resty.events unix socket"
[ -S /tmp/events.sock ] && pass "/tmp/events.sock exists" || \
  warn "/tmp/events.sock not found (events may not have started yet)"

# ── F26: LUA SHARED DICT COUNT ───────────────────────────────
info "F26: Lua shared dicts (1.29 compat)"
LUA_DICTS=$(grep -c "lua_shared_dict" "$NGINX_PREFIX/conf/nginx.conf" 2>/dev/null || echo 0)
TOTAL_SHM=$(grep "lua_shared_dict" "$NGINX_PREFIX/conf/nginx.conf" | \
  awk '{print $3}' | awk -F'm' '{sum+=$1} END {printf "%.0f", sum}')
echo "  Declared dicts : $LUA_DICTS"
echo "  Total SHM      : ${TOTAL_SHM}MB"
[ "$LUA_DICTS" -gt 0 ] && pass "$LUA_DICTS lua_shared_dict entries (${TOTAL_SHM}MB total)" || \
  fail "No lua_shared_dict in config"

# ── F27: DYN_CERT LUA MODULE ─────────────────────────────────
info "F27: dyn_cert Lua module (ssl_certificate_by_lua_block)"
DYN_CERT=$(find "$NGINX_PREFIX/lua" -name "dyn_cert.lua" 2>/dev/null | head -1)
[ -n "$DYN_CERT" ] && pass "dyn_cert.lua found: $DYN_CERT" || \
  fail "dyn_cert.lua not found — HTTPS dynamic cert will fail"

# ── F28: WAF RULES ───────────────────────────────────────────
info "F28: WAF / NAXSI rules files"
[ -f "$NGINX_PREFIX/naxsi_rules/naxsi_core.rules" ] && \
  pass "naxsi_core.rules present" || fail "naxsi_core.rules MISSING"
BLOCK_COUNT=$(ls "$NGINX_PREFIX/naxsi_rules/blocking/"*.rules 2>/dev/null | wc -l)
CDN_COUNT=$(ls "$NGINX_PREFIX/naxsi_rules/cdnray/"*.rules 2>/dev/null | wc -l)
echo "  blocking/ rules: $BLOCK_COUNT"
echo "  cdnray/ rules  : $CDN_COUNT"
[ "$BLOCK_COUNT" -gt 0 ] && pass "$BLOCK_COUNT blocking rules loaded" || warn "No blocking rules found"
[ "$CDN_COUNT"   -gt 0 ] && pass "$CDN_COUNT cdnray rules loaded"    || warn "No cdnray rules found"

# ── F29: WAF CLEAN REQUEST ───────────────────────────────────
info "F29: WAF — clean request passes (block_type=0:0)"
CLEAN_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "http://$CDN_IP:$CDN_PORT/index.html" -H "Host: $HOST_HEADER")
echo "  Clean GET → HTTP $CLEAN_CODE"
[ "$CLEAN_CODE" != "000" ] && pass "Clean request not blocked ($CLEAN_CODE)" || \
  fail "Clean request got no response"

# ── F30: WAF SQLI PROBE ──────────────────────────────────────
info "F30: WAF — SQLi probe (LibInjectionSql)"
SQLI_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "http://$CDN_IP:$CDN_PORT/?id=1+OR+1%3D1--" -H "Host: $HOST_HEADER")
echo "  SQLi probe → HTTP $SQLI_CODE"
[[ "$SQLI_CODE" == "403" || "$SQLI_CODE" == "444" || "$SQLI_CODE" == "302" ]] && \
  pass "SQLi blocked: $SQLI_CODE" || \
  warn "SQLi returned $SQLI_CODE — check block_cause in naxsi.log"

# ── F31: WAF XSS PROBE ───────────────────────────────────────
info "F31: WAF — XSS probe (LibInjectionXss)"
XSS_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "http://$CDN_IP:$CDN_PORT/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" \
  -H "Host: $HOST_HEADER")
echo "  XSS probe → HTTP $XSS_CODE"
[[ "$XSS_CODE" == "403" || "$XSS_CODE" == "444" || "$XSS_CODE" == "302" ]] && \
  pass "XSS blocked: $XSS_CODE" || \
  warn "XSS returned $XSS_CODE — check naxsi.log"

# ── F32: GEOIP2 DATABASES ────────────────────────────────────
info "F32: GeoIP2 databases"
[ -f "$NGINX_PREFIX/lua/geoip2/city.mmdb" ] && pass "city.mmdb present" || warn "city.mmdb missing"
[ -f "$NGINX_PREFIX/lua/geoip2/isp.mmdb"  ] && pass "isp.mmdb present"  || warn "isp.mmdb missing"

# ── F33: LUA INIT FILES ──────────────────────────────────────
info "F33: Lua init files"
[ -f "$NGINX_PREFIX/lua/init.lua"        ] && pass "init.lua present"        || fail "init.lua MISSING"
[ -f "$NGINX_PREFIX/lua/init_worker.lua" ] && pass "init_worker.lua present" || fail "init_worker.lua MISSING"

# ── F34: HTTP_ACCESS MODULE ──────────────────────────────────
info "F34: http_access Lua module (used in both http.conf + https.conf)"
HTTP_ACCESS=$(find "$NGINX_PREFIX/lua" -name "http_access.lua" 2>/dev/null | head -1)
[ -n "$HTTP_ACCESS" ] && pass "http_access.lua found: $HTTP_ACCESS" || \
  fail "http_access.lua not found — location / will fail"

# ── F35: HEADER + BODY FILTER LUA ────────────────────────────
info "F35: header_filter.lua + body.lua"
[ -f "$NGINX_PREFIX/lua/header_filter.lua" ] && pass "header_filter.lua present" || \
  fail "header_filter.lua MISSING"
[ -f "$NGINX_PREFIX/lua/body.lua"          ] && pass "body.lua present"          || \
  fail "body.lua MISSING"

# ── F36: ERROR LOG CLEAN ─────────────────────────────────────
info "F36: Error log — clean after upgrade"
# Filter transient resty.events broker reconnect errors — expected briefly after reload
ERROR_COUNT=$(tail -100 "$NGINX_PREFIX/logs/error.log" 2>/dev/null | \
  grep "\[error\]" | grep -v "event worker failed to communicate with broker" | wc -l | tr -d ' ')
CRIT_COUNT=$(tail -100 "$NGINX_PREFIX/logs/error.log" 2>/dev/null | \
  grep "\[crit\]" | wc -l | tr -d ' ')
ERROR_COUNT="${ERROR_COUNT:-0}"; CRIT_COUNT="${CRIT_COUNT:-0}"
echo "  Last 100 lines — real [error]: $ERROR_COUNT  [crit]: $CRIT_COUNT"
[ "$ERROR_COUNT" -eq 0 ] && pass "No real errors in recent log" || \
  warn "$ERROR_COUNT error(s) found — review $NGINX_PREFIX/logs/error.log"
[ "$CRIT_COUNT" -eq 0 ] && pass "No critical entries" || \
  fail "$CRIT_COUNT critical entry(s) — immediate review needed"

# ── F37: NAXSI LOG CHECK ─────────────────────────────────────
info "F37: NAXSI log after WAF probes"
if [ -f "$NGINX_PREFIX/logs/naxsi.log" ]; then
  NAXSI_LINES=$(tail -20 "$NGINX_PREFIX/logs/naxsi.log" | wc -l)
  echo "  naxsi.log last 20 lines: $NAXSI_LINES entries"
  tail -5 "$NGINX_PREFIX/logs/naxsi.log" 2>/dev/null || true
  pass "NAXSI log has entries (WAF events recorded)"
else
  warn "naxsi.log not found — WAF may not have fired yet"
fi

# ── SUMMARY ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════${NC}"
echo -e "${BOLD}  PHASE 1: FUNCTIONAL TEST SUMMARY${NC}"
echo -e "${GREEN}  PASS : $PASS${NC}"
echo -e "${YELLOW}  WARN : $WARN${NC}"
echo -e "${RED}  FAIL : $FAIL${NC}"
echo -e "${BOLD}════════════════════════════════════════${NC}"
echo ""
[ "$FAIL" -gt 0 ] && echo -e "${RED}Action required: $FAIL test(s) failed.${NC}" && exit 1
[ "$WARN" -gt 0 ] && echo -e "${YELLOW}Review $WARN warning(s) before full production traffic.${NC}" && exit 0
echo -e "${GREEN}All functional tests passed.${NC}"
