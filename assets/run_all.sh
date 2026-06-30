#!/usr/bin/env bash
# ============================================================
#  MASTER RUNNER — OpenResty 1.27 → 1.29 upgrade test suite
#  CDN IP  : 172.105.75.48
#  Domains : www.linhu110.com  |  www.lkiuouqijgkdhcnxshh.xyz
#
#  Usage:
#    bash run_all.sh
#    bash run_all.sh --host www.linhu110.com
#    bash run_all.sh --host www.lkiuouqijgkdhcnxshh.xyz
# ============================================================
set -uo pipefail

# ── Defaults — hardcoded for this CDN server ─────────────────
export CDN_IP="172.105.75.48"
export CDN_PORT="${CDN_PORT:-80}"
export CDN_HTTPS_PORT="${CDN_HTTPS_PORT:-443}"
export HOST_HEADER="${HOST_HEADER:-www.linhu110.com}"
export CONCURRENCY="${CONCURRENCY:-50}"
export REQUESTS="${REQUESTS:-5000}"
export DURATION="${DURATION:-30}"

# ── Parse optional --host override ───────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) export HOST_HEADER="$2"; shift 2 ;;
    --concurrency) export CONCURRENCY="$2"; shift 2 ;;
    --requests) export REQUESTS="$2"; shift 2 ;;
    --duration) export DURATION="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; shift ;;
  esac
done

# ── Log setup ────────────────────────────────────────────────
LOG_DIR="/var/log/cdn-tests"
mkdir -p "$LOG_DIR"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$LOG_DIR/cdn-test-${TIMESTAMP}.log"
SUMMARY_FILE="$LOG_DIR/cdn-test-${TIMESTAMP}-summary.txt"

# Tee everything — stdout to terminal AND log file (strip ANSI for log)
exec > >(tee >(sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE")) 2>&1

BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PHASE1_STATUS="NOT RUN"
PHASE2_STATUS="NOT RUN"
PHASE3_STATUS="NOT RUN"
OVERALL_PASS=true

# ── Banner ───────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║      CDN OPENRESTY 1.27 → 1.29  TEST SUITE          ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  CDN IP       : $CDN_IP"
echo "  Host header  : $HOST_HEADER"
echo "  HTTP port    : $CDN_PORT"
echo "  HTTPS port   : $CDN_HTTPS_PORT"
echo "  Concurrency  : $CONCURRENCY"
echo "  Requests     : $REQUESTS"
echo "  Duration     : ${DURATION}s"
echo "  Started      : $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Log file     : $LOG_FILE"
echo "  Summary file : $SUMMARY_FILE"
echo ""

# ── Phase runner ─────────────────────────────────────────────
run_phase() {
  local num="$1" script="$2" name="$3" phase_var="$4"
  echo ""
  echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║  PHASE $num: $name${NC}"
  echo -e "${BOLD}║  Started: $(date '+%H:%M:%S')${NC}"
  echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
  echo ""

  local start_ts=$SECONDS
  if bash "$DIR/$script"; then
    local elapsed=$(( SECONDS - start_ts ))
    echo ""
    echo -e "${GREEN}  Phase $num PASSED in ${elapsed}s${NC}"
    eval "$phase_var=PASSED"
  else
    local elapsed=$(( SECONDS - start_ts ))
    echo ""
    echo -e "${RED}  Phase $num FAILED after ${elapsed}s — review output above${NC}"
    eval "$phase_var=FAILED"
    OVERALL_PASS=false
  fi
}

run_phase 1 "01_functional.sh"  "FUNCTIONAL / INTEGRATION TESTING"  PHASE1_STATUS
run_phase 2 "02_performance.sh" "TRAFFIC & PERFORMANCE VALIDATION"   PHASE2_STATUS
run_phase 3 "03_rollback.sh"    "ROLLBACK TESTING"                   PHASE3_STATUS

# ── Final summary ────────────────────────────────────────────
END_TIME="$(date '+%Y-%m-%d %H:%M:%S')"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║                  TEST RUN SUMMARY                   ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  CDN IP     : $CDN_IP                     ║${NC}"
echo -e "${BOLD}║  Domain     : $HOST_HEADER${NC}"
echo -e "${BOLD}║  Completed  : $END_TIME                   ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════╣${NC}"

status_line() {
  local label="$1" status="$2"
  if [ "$status" = "PASSED" ]; then
    echo -e "${BOLD}║  $label : ${GREEN}$status${NC}${BOLD}                              ║${NC}"
  elif [ "$status" = "FAILED" ]; then
    echo -e "${BOLD}║  $label : ${RED}$status${NC}${BOLD}                              ║${NC}"
  else
    echo -e "${BOLD}║  $label : ${YELLOW}$status${NC}${BOLD}                           ║${NC}"
  fi
}

status_line "Phase 1 — Functional " "$PHASE1_STATUS"
status_line "Phase 2 — Performance" "$PHASE2_STATUS"
status_line "Phase 3 — Rollback   " "$PHASE3_STATUS"

echo -e "${BOLD}╠══════════════════════════════════════════════════════╣${NC}"
if $OVERALL_PASS; then
  echo -e "${BOLD}║  Overall : ${GREEN}ALL PHASES PASSED ✓${NC}${BOLD}                    ║${NC}"
else
  echo -e "${BOLD}║  Overall : ${RED}ONE OR MORE PHASES FAILED ✗${NC}${BOLD}             ║${NC}"
fi
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Full log  : $LOG_FILE"
echo "  Summary   : $SUMMARY_FILE"
echo ""

# ── Write plain-text summary file ────────────────────────────
{
  echo "=================================================="
  echo "  CDN TEST SUITE — RUN SUMMARY"
  echo "=================================================="
  echo "  CDN IP        : $CDN_IP"
  echo "  Domain        : $HOST_HEADER"
  echo "  HTTP port     : $CDN_PORT"
  echo "  HTTPS port    : $CDN_HTTPS_PORT"
  echo "  Concurrency   : $CONCURRENCY"
  echo "  Requests      : $REQUESTS"
  echo "  Duration      : ${DURATION}s"
  echo "  Timestamp     : $TIMESTAMP"
  echo "  Completed     : $END_TIME"
  echo "--------------------------------------------------"
  echo "  Phase 1 (Functional)  : $PHASE1_STATUS"
  echo "  Phase 2 (Performance) : $PHASE2_STATUS"
  echo "  Phase 3 (Rollback)    : $PHASE3_STATUS"
  echo "--------------------------------------------------"
  if $OVERALL_PASS; then
    echo "  OVERALL RESULT : ALL PASSED"
  else
    echo "  OVERALL RESULT : FAILED — review $LOG_FILE"
  fi
  echo "=================================================="
  echo ""
  echo "  PASS/FAIL/WARN counts from full log:"
  grep -E "^\[PASS\]|^\[FAIL\]|^\[WARN\]" "$LOG_FILE" 2>/dev/null | \
    awk 'BEGIN{p=0;f=0;w=0}
         /^\[PASS\]/{p++} /^\[FAIL\]/{f++} /^\[WARN\]/{w++}
         END{printf "  PASS: %d  FAIL: %d  WARN: %d\n", p, f, w}'
  echo ""
  echo "  Failed tests:"
  grep "^\[FAIL\]" "$LOG_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (none)"
  echo ""
  echo "  Warnings:"
  grep "^\[WARN\]" "$LOG_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (none)"
  echo "=================================================="
} > "$SUMMARY_FILE"

echo "  Quick view of failures:"
grep "\[FAIL\]" "$LOG_FILE" 2>/dev/null | head -20 || echo "  No failures recorded."
echo ""

$OVERALL_PASS && exit 0 || exit 1
