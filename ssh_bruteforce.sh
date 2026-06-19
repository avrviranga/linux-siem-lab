#!/bin/bash
# ================================================================
#  ssh_bruteforce.sh
#  Detects SSH brute force attempts from /var/log/auth.log
#  Author : RH Vitharana | SLIIT — BSc (Hons) IT (Cyber Security)
#  Usage  : sudo bash ssh_bruteforce.sh [threshold]
#  Example: sudo bash ssh_bruteforce.sh 3
# ================================================================

LOGFILE="/var/log/auth.log"
REPORT_DIR="/opt/siem-project/reports"
REPORT="$REPORT_DIR/ssh_report_$(date +%Y-%m-%d_%H-%M).txt"
THRESHOLD="${1:-5}"   # default: 5 attempts = suspicious

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; RESET='\033[0m'

# Validate log file exists
if [ ! -f "$LOGFILE" ]; then
  echo -e "${RED}[✘] Log file not found: $LOGFILE${RESET}"
  exit 1
fi

mkdir -p "$REPORT_DIR"

# ── Build report ─────────────────────────────────────────────────
{
echo "============================================"
echo "  SSH Brute Force Detection Report"
echo "  Generated : $(date)"
echo "  System    : $(hostname)"
echo "  Threshold : $THRESHOLD attempts triggers ALERT"
echo "============================================"

echo -e "\n[+] ATTACKING IPs (attempts >= $THRESHOLD):"
grep "Failed password" "$LOGFILE" \
  | awk '{print $11}' \
  | sort | uniq -c | sort -rn \
  | while read count ip; do
      if [ "$count" -ge "$THRESHOLD" ]; then
        echo "  ALERT  | $ip | $count failed attempts"
      else
        echo "  WATCH  | $ip | $count failed attempts"
      fi
    done

echo -e "\n[+] TOP TARGETED USERNAMES:"
grep "Failed password" "$LOGFILE" \
  | awk '{print $9}' \
  | sort | uniq -c | sort -rn \
  | head -10 \
  | while read count user; do
      echo "  $count attempts on user: $user"
    done

echo -e "\n[+] INVALID USER ATTEMPTS:"
grep "Invalid user" "$LOGFILE" \
  | awk '{print $8, $10}' \
  | sort | uniq -c | sort -rn \
  | head -10

echo -e "\n[+] SUCCESSFUL LOGINS:"
grep "Accepted password\|Accepted publickey" "$LOGFILE" \
  | awk '{print $1, $2, $3, "| user:", $9, "| from:", $11}' \
  | tail -20

echo -e "\n[+] SUDO ACTIVITY:"
grep "sudo" "$LOGFILE" | grep "COMMAND" \
  | awk '{print $1, $2, $3, $5, $6}' \
  | tail -10

echo -e "\n[+] SUMMARY STATS:"
echo "  Total failed attempts : $(grep -c 'Failed password' $LOGFILE)"
echo "  Total invalid users   : $(grep -c 'Invalid user' $LOGFILE)"
echo "  Total successful SSH  : $(grep -c 'Accepted' $LOGFILE)"
echo "  Unique attacking IPs  : $(grep 'Failed password' $LOGFILE | awk '{print $11}' | sort -u | wc -l)"
echo "============================================"
} > "$REPORT"

# ── Display report ────────────────────────────────────────────────
cat "$REPORT"
echo -e "\n${GREEN}[*] Report saved: $REPORT${RESET}"
