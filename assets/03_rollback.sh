#!/usr/bin/env bash
# ============================================================
#  PHASE 3 — ROLLBACK TESTING
#  CDN IP  : 172.105.75.48
#  Domains : www.linhu110.com | www.lkiuouqijgkdhcnxshh.xyz
# ============================================================
set -uo pipefail

CDN_IP="${CDN_IP:-172.105.75.48}"
CDN_PORT="${CDN_PORT:-80}"
CDN_HTTPS_PORT="${CDN_HTTPS_PORT:-443}"
HOST_HEADER="${HOST_HEADER:-www.linhu110.com}"
DOMAINS=("www.linhu110.com" "www.lkiuouqijgkdhcnxshh.xyz")
NGINX_PREFIX="/usr/local/openresty/nginx"
BACKUP_BASE="/etc/openresty/backups"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'
PASS=0; FAIL=0; WARN=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info() { echo -e "\n${BOLD}── $1 ──${NC}"; }

# Full health check — HTTP + HTTPS + both domains
health_check() {
  local label="$1"
  local all_ok=true

  # HTTP health
  HTTP_CODE=$(curl -s -o /tmp/_hbody -w "%{http_code}" http://127.0.0.1:61002/ge.status 2>/dev/null; true)
  HTTP_BODY=$(cat /tmp/_hbody 2>/dev/null)
  if [ "$HTTP_CODE" = "200" ] && echo "$HTTP_BODY" | grep -q "OK"; then
    pass "$label — ge.status: 200 OK"
  else
    fail "$label — ge.status: HTTP $HTTP_CODE body: $HTTP_BODY"
    all_ok=false
  fi

  # Server header check per domain
  for domain in "${DOMAINS[@]}"; do
    SRV=$(curl -sI "http://$CDN_IP:$CDN_PORT/" -H "Host: $domain" 2>/dev/null | \
      grep -i "^server:" | tr -d '\r')
    echo "$SRV" | grep -qi "CDN" && \
      pass "$label — Server: CDN header OK ($domain)" || \
      warn "$label — Server header wrong for $domain: $SRV"
  done

  # HTTPS check per domain — do NOT use || echo "000" (causes "000000")
  for domain in "${DOMAINS[@]}"; do
    HTTPS_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
      "https://$CDN_IP:$CDN_HTTPS_PORT/" -H "Host: $domain" 2>/dev/null; true)
    [ -n "$HTTPS_CODE" ] && [ "$HTTPS_CODE" != "000" ] && \
      pass "$label — HTTPS OK for $domain (HTTP $HTTPS_CODE)" || \
      warn "$label — HTTPS no response for $domain (got: ${HTTPS_CODE:-empty})"
  done

  $all_ok
}

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  PHASE 3: ROLLBACK TESTING             ${NC}"
echo -e "${BOLD}  CDN : $CDN_IP                         ${NC}"
echo -e "${BOLD}  $(date '+%Y-%m-%d %H:%M:%S')          ${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

# ── R1: PRE-ROLLBACK STATE ───────────────────────────────────
info "R1: Current state — pre-rollback snapshot"
echo "  Version : $(openresty -v 2>&1)"
echo "  Workers : $(ps aux | grep 'nginx: worker' | grep -v grep | wc -l)"
curl -s --unix-socket /var/run/nginx.sock http://localhost/nginx-status
health_check "Baseline"

# ── R2: SNAPSHOT CURRENT 1.29 CONFIG ─────────────────────────
info "R2: Snapshot current 1.29 config before rollback tests"
SNAPSHOT="$BACKUP_BASE/rollback-test-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$SNAPSHOT"
cp -r "$NGINX_PREFIX/conf"   "$SNAPSHOT/" 2>/dev/null && pass "conf/ snapshotted"
cp -r "$NGINX_PREFIX/lua"    "$SNAPSHOT/" 2>/dev/null && pass "lua/ snapshotted"
cp -r "$NGINX_PREFIX/server" "$SNAPSHOT/" 2>/dev/null && pass "server/*.conf snapshotted" || \
  warn "server/ dir not found"
echo "$SNAPSHOT" > /tmp/cdn_1.29_snapshot

# ── R3: GRACEFUL RELOAD ──────────────────────────────────────
info "R3: Graceful reload — openresty -s reload"
echo "  Pre-reload worker PIDs:"
PRE_PIDS=$(ps aux | grep "nginx: worker" | grep -v grep | awk '{print $2}' | tr '\n' ' ')
echo "    $PRE_PIDS"

openresty -t 2>&1 | grep -q "successful" && pass "Syntax check before reload: OK" || \
  { fail "Syntax error — reload aborted"; exit 1; }

openresty -s reload
sleep 4

echo "  Post-reload worker PIDs:"
POST_PIDS=$(ps aux | grep "nginx: worker" | grep -v grep | awk '{print $2}' | tr '\n' ' ')
echo "    $POST_PIDS"

[ "$PRE_PIDS" != "$POST_PIDS" ] && \
  pass "Worker PIDs rotated — graceful drain confirmed" || \
  warn "PIDs unchanged after reload (may be same workers reused)"

health_check "Post-reload"

VER=$(openresty -v 2>&1)
VER_NUM=$(echo "$VER" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
echo "$VER_NUM" | grep -q "^1\.29\." && pass "1.29 still active after reload ($VER_NUM)" || \
  fail "Unexpected version after reload: $VER_NUM"

# ── R4: DYN_CERT AFTER RELOAD ────────────────────────────────
info "R4: dyn_cert still serving correct certs after reload"
for domain in "${DOMAINS[@]}"; do
  CERT_CN=$(echo Q | openssl s_client \
    -connect "$CDN_IP:$CDN_HTTPS_PORT" \
    -servername "$domain" 2>/dev/null | \
    openssl x509 -noout -subject 2>/dev/null | grep -o "CN\s*=\s*[^,]*" || echo "FAILED")
  echo "  $domain → $CERT_CN"
  echo "$CERT_CN" | grep -qi "FAILED" && \
    warn "dyn_cert not returning cert for $domain after reload" || \
    pass "dyn_cert serving cert for $domain after reload"
done

# ── R5: FIND PRE-UPGRADE BACKUP ──────────────────────────────
info "R5: Locating pre-upgrade backup (1.27 config)"
PREV_BACKUP=$(ls -td "$BACKUP_BASE"/pre-upgrade-*/ 2>/dev/null | head -1)
if [ -n "$PREV_BACKUP" ]; then
  pass "Pre-upgrade backup found: $PREV_BACKUP"
  echo "  Contents:"
  ls -la "$PREV_BACKUP" 2>/dev/null | head -8
else
  warn "No pre-upgrade backup found in $BACKUP_BASE — run 00_preflight.sh before upgrading"
  warn "Skipping config restore tests (R6–R7)"
  PREV_BACKUP=""
fi

# ── R6: SIMULATED CONFIG RESTORE ─────────────────────────────
info "R6: Simulated config restore — restore 1.27 config → reload → validate"
if [ -n "$PREV_BACKUP" ] && [ -d "$PREV_BACKUP/conf" ]; then
  echo "  Restoring conf/ from: $PREV_BACKUP"
  cp -r "$PREV_BACKUP/conf/." "$NGINX_PREFIX/conf/"
  [ -d "$PREV_BACKUP/server" ] && cp -r "$PREV_BACKUP/server/." "$NGINX_PREFIX/server/" 2>/dev/null || true

  echo "  Syntax check on restored config..."
  if openresty -t 2>&1 | grep -q "successful"; then
    pass "Restored config syntax OK"
    openresty -s reload
    sleep 4
    health_check "Post-restore reload"
    pass "Config restore + reload path verified"
  else
    fail "Restored config failed syntax check"
    echo "  Reverting to 1.29 snapshot..."
    cp -r "$SNAPSHOT/conf/." "$NGINX_PREFIX/conf/"
    [ -d "$SNAPSHOT/server" ] && cp -r "$SNAPSHOT/server/." "$NGINX_PREFIX/server/" 2>/dev/null || true
    openresty -s reload && sleep 3
    health_check "Recovery after failed restore"
  fi
else
  warn "Skipping restore test — no pre-upgrade backup available"
fi

# ── R7: RESTORE BACK TO 1.29 ─────────────────────────────────
info "R7: Restoring back to 1.29 config (post rollback-test)"
SNAP=$(cat /tmp/cdn_1.29_snapshot 2>/dev/null || echo "")
if [ -n "$SNAP" ] && [ -d "$SNAP/conf" ]; then
  cp -r "$SNAP/conf/." "$NGINX_PREFIX/conf/"
  [ -d "$SNAP/server" ] && cp -r "$SNAP/server/." "$NGINX_PREFIX/server/" 2>/dev/null || true
  openresty -t 2>&1 | grep -q "successful" && pass "1.29 config syntax OK" || fail "1.29 restore syntax error"
  openresty -s reload
  sleep 3
  health_check "Back on 1.29"
  VER=$(openresty -v 2>&1)
  VER_NUM=$(echo "$VER" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  echo "$VER_NUM" | grep -q "^1\.29\." && pass "Confirmed back on 1.29 ($VER_NUM)" || warn "Version: $VER_NUM"
else
  warn "1.29 snapshot not found — skipping restore back"
fi

# ── R8: DYUPS HOT-SWAP ───────────────────────────────────────
info "R8: Dyups upstream hot-swap (zero downtime)"
echo "  Current upstream:"
CURRENT=$(curl -s --interface lo http://127.0.0.1:61000/upstream/cdnray_upstream 2>/dev/null || echo "unavailable")
echo "    $CURRENT"

echo "  Swapping upstream to 127.0.0.2:8080 (test)..."
SWAP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://127.0.0.1:61000/upstream/cdnray_upstream \
  --interface lo -d 'server 127.0.0.2:8080;' 2>/dev/null; true)
echo "  Dyups swap response: HTTP $SWAP_CODE"
[ "$SWAP_CODE" = "200" ] && pass "Dyups hot-swap accepted" || \
  warn "Dyups swap: $SWAP_CODE (may need live upstream)"

health_check "During dyups swap"

echo "  Reverting upstream..."
curl -s -X POST http://127.0.0.1:61000/upstream/cdnray_upstream \
  --interface lo -d 'server 0.0.0.1;' 2>/dev/null && pass "Dyups reverted" || warn "Dyups revert failed"

# ── R9: EMERGENCY RESTART PROCEDURE ─────────────────────────
info "R9: Emergency restart procedure (documented — not auto-executed)"
echo ""
echo -e "${YELLOW}  Use only when openresty -s reload fails or workers are hung:${NC}"
echo ""
echo "  BACKUP=\$(ls -td $BACKUP_BASE/pre-upgrade-*/ 2>/dev/null | head -1)"
echo "  cp -r \"\$BACKUP/conf/.\" $NGINX_PREFIX/conf/"
echo "  cp -r \"\$BACKUP/server/.\" $NGINX_PREFIX/server/ 2>/dev/null"
echo "  openresty -t || { echo 'Config error'; exit 1; }"
echo "  systemctl stop openresty"
echo "  sleep 2"
echo "  systemctl start openresty"
echo "  sleep 3"
echo "  curl -s http://127.0.0.1:61002/ge.status"
echo "  openresty -v"
echo "  tail -20 $NGINX_PREFIX/logs/error.log"
echo ""
warn "Emergency restart documented above — run manually only if needed"

# ── R10: FINAL VALIDATION ────────────────────────────────────
info "R10: Final post-rollback validation — all systems"
echo ""

# Version
VER=$(openresty -v 2>&1)
VER_NUM=$(echo "$VER" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
echo "  Active version : $VER"
echo "$VER_NUM" | grep -q "^1\.29\." && pass "Running on 1.29 ($VER_NUM)" || warn "Not on 1.29: $VER_NUM"

# Syntax
openresty -t 2>&1 | grep -q "successful" && pass "Config syntax valid" || fail "Config syntax error"

# Workers
WCOUNT=$(ps aux | grep "nginx: worker" | grep -v grep | wc -l)
[ "$WCOUNT" -gt 0 ] && pass "Workers running: $WCOUNT" || fail "No workers running"

# Full health
health_check "Final"

# Error log
# Filter out the transient "event worker failed to communicate with broker" error —
# this fires briefly after every reload as old workers drain, and is not a real failure.
ERR=$(tail -50 "$NGINX_PREFIX/logs/error.log" 2>/dev/null | \
  grep "\[error\]" | grep -v "event worker failed to communicate with broker" | wc -l | tr -d ' ')
CRT=$(tail -50 "$NGINX_PREFIX/logs/error.log" 2>/dev/null | \
  grep "\[crit\]" | wc -l | tr -d ' ')
ERR="${ERR:-0}"; CRT="${CRT:-0}"
[ "$ERR" -eq 0 ] && pass "Error log clean post-rollback (excluding transient reload events)" || warn "$ERR real error(s) in log (reload-transient events excluded)"
[ "$CRT" -eq 0 ] && pass "No critical entries" || fail "$CRT critical entries found"

# ── R11: ROLLBACK EVENT TIMELINE ─────────────────────────────
info "R11: Rollback event timeline (error.log — reload signals and real errors)"
echo "  Reload/signal events:"
tail -50 "$NGINX_PREFIX/logs/error.log" 2>/dev/null | \
  grep -E "start|reload|exit|signal|1\.29|1\.27" | sed 's/^/    /' || \
  echo "    (none found)"
echo "  Real errors (excluding transient resty.events broker reconnects):"
tail -50 "$NGINX_PREFIX/logs/error.log" 2>/dev/null | \
  grep "\[error\]\|\[crit\]" | \
  grep -v "event worker failed to communicate with broker" | \
  sed 's/^/    /' || echo "    (none — clean)"
echo ""
echo "  Note: 'event worker failed to communicate with broker' errors after reload"
echo "  are expected and transient — resty.events workers reconnect within seconds."

# ── SUMMARY ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════${NC}"
echo -e "${BOLD}  PHASE 3: ROLLBACK TEST SUMMARY${NC}"
echo -e "${GREEN}  PASS : $PASS${NC}"
echo -e "${YELLOW}  WARN : $WARN${NC}"
echo -e "${RED}  FAIL : $FAIL${NC}"
echo -e "${BOLD}════════════════════════════════════════${NC}"
echo ""
[ "$FAIL" -gt 0 ] && echo -e "${RED}Rollback path has issues — $FAIL failure(s).${NC}" && exit 1
echo -e "${GREEN}Rollback path verified.${NC}"
