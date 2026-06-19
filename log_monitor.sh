#!/bin/bash
# ================================================================
#  log_monitor.sh
#  Monitors key log files for critical security keywords
#  Author : RH Vitharana | SLIIT — BSc (Hons) IT (Cyber Security)
#  Usage  : sudo bash log_monitor.sh
# ================================================================

LOGS=(
  "/var/log/auth.log"
  "/var/log/syslog"
  "/var/log/kern.log"
  "/var/log/dpkg.log"
)

KEYWORDS=("error" "critical" "failed" "denied" "invalid" "attack" "warning" "refused" "unauthorized")

REPORT_DIR="/opt/siem-project/reports"
REPORT="$REPORT_DIR/log_health_$(date +%Y-%m-%d_%H-%M).txt"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'

mkdir -p "$REPORT_DIR"

{
echo "========================================"
echo "  Log Health Monitor Report"
echo "  Generated : $(date)"
echo "  System    : $(hostname)"
echo "========================================"

TOTAL_ISSUES=0

for log in "${LOGS[@]}"; do
  if [ ! -f "$log" ]; then
    echo -e "\n--- $log --- [NOT FOUND — skipping]"
    continue
  fi

  echo -e "\n--- $log ---"
  FILE_ISSUES=0

  for keyword in "${KEYWORDS[@]}"; do
    count=$(grep -ic "$keyword" "$log" 2>/dev/null)
    if [ "$count" -gt 0 ]; then
      echo "  [$keyword]: $count occurrences"
      FILE_ISSUES=$((FILE_ISSUES + count))
    fi
  done

  [ "$FILE_ISSUES" -eq 0 ] && echo "  [clean] No issues found"
  TOTAL_ISSUES=$((TOTAL_ISSUES + FILE_ISSUES))
done

echo -e "\n========================================"
echo "  Total issues across all logs: $TOTAL_ISSUES"
echo "========================================"
} | tee "$REPORT"

echo -e "\n${GREEN}[*] Report saved: $REPORT${RESET}"
