#!/bin/bash
# ================================================================
#  03_install_scripts.sh  (CLEAN REWRITE v2)
#  Installs ssh_bruteforce.sh, log_monitor.sh, siem_status.sh
#  and cron jobs.
#
#  FIXES vs original:
#    • ssh_bruteforce uses regex extraction (not awk field numbers)
#      so it works correctly on Ubuntu 22.04+ ISO 8601 log format
#    • log_monitor report is richer — shows top keywords per file
#    • siem_status shows index doc counts and cron status clearly
#
#  Author : RH Vitharana | SLIIT — BSc (Hons) IT (Cyber Security)
#  Usage  : sudo bash 03_install_scripts.sh
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

INSTALL_DIR="/opt/siem-project"
SCRIPT_DIR="$INSTALL_DIR/scripts"
REPORT_DIR="$INSTALL_DIR/reports"
LOG_DIR="$INSTALL_DIR/logs"
SETUP_LOG="$LOG_DIR/scripts_install_$(date +%Y-%m-%d_%H-%M-%S).log"

log()     { echo -e "${GREEN}[✔]${RESET} $1" | tee -a "$SETUP_LOG"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1" | tee -a "$SETUP_LOG"; }
error()   { echo -e "${RED}[✘]${RESET} $1" | tee -a "$SETUP_LOG"; exit 1; }
info()    { echo -e "${CYAN}[i]${RESET} $1" | tee -a "$SETUP_LOG"; }
section() { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━${RESET}" | tee -a "$SETUP_LOG"; }

mkdir -p "$LOG_DIR" "$SCRIPT_DIR" "$REPORT_DIR"
touch "$SETUP_LOG"

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash 03_install_scripts.sh"

# ══════════════════════════════════════════════════════════════════
# ssh_bruteforce.sh  (v2 — regex-based IP/user extraction)
# ══════════════════════════════════════════════════════════════════
section "Writing ssh_bruteforce.sh"
cat > "$SCRIPT_DIR/ssh_bruteforce.sh" << 'EOF'
#!/bin/bash
# ================================================================
#  ssh_bruteforce.sh  v2 — Ubuntu 22.04+ ISO 8601 log format
#  Uses regex extraction instead of fixed awk field numbers
#  Author : RH Vitharana | SLIIT — BSc (Hons) IT (Cyber Security)
#  Usage  : sudo bash ssh_bruteforce.sh [threshold]
# ================================================================

LOGFILE="/var/log/auth.log"
REPORT_DIR="/opt/siem-project/reports"
REPORT="$REPORT_DIR/ssh_report_$(date +%Y-%m-%d_%H-%M).txt"
THRESHOLD="${1:-5}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

[ ! -f "$LOGFILE" ] && echo -e "${RED}[✘] $LOGFILE not found${RESET}" && exit 1
mkdir -p "$REPORT_DIR"

# Extract IPv4 or IPv6 after the word "from"
extract_ip()   { grep -oP '(?<=from )(\d{1,3}\.){3}\d{1,3}|(?<=from )[0-9a-fA-F:]+(?= port)'; }
# Extract username (last word before "from"), skipping "invalid user" prefix
extract_user() { grep -oP '(?<=for )(invalid user )?\K\S+(?= from)'; }

{
echo "============================================"
echo "  SSH Brute Force Detection Report"
echo "  Generated : $(date)"
echo "  System    : $(hostname)"
echo "  Threshold : $THRESHOLD attempts triggers ALERT"
echo "  Log file  : $LOGFILE"
echo "  Log lines : $(wc -l < "$LOGFILE")"
echo "============================================"

# ── Attacking IPs ───────────────────────────────────────────────
echo -e "\n[+] ATTACKING IPs (all Failed password attempts):"
grep "Failed password" "$LOGFILE" | extract_ip \
  | sort | uniq -c | sort -rn \
  | while read -r count ip; do
      [[ "$ip" =~ ^[0-9a-fA-F:.]+$ ]] || continue
      if [ "$count" -ge "$THRESHOLD" ]; then
        echo "  ALERT  | $ip | $count failed attempts"
      else
        echo "  WATCH  | $ip | $count failed attempts"
      fi
    done

# ── Invalid user probes by IP ───────────────────────────────────
echo -e "\n[+] INVALID USER PROBES BY IP:"
grep "Invalid user" "$LOGFILE" | extract_ip \
  | sort | uniq -c | sort -rn \
  | while read -r count ip; do
      [[ "$ip" =~ ^[0-9a-fA-F:.]+$ ]] || continue
      echo "  $count probes from $ip"
    done

# ── Top targeted usernames ──────────────────────────────────────
echo -e "\n[+] TOP TARGETED USERNAMES (Failed password):"
grep "Failed password" "$LOGFILE" | extract_user \
  | sort | uniq -c | sort -rn | head -10 \
  | while read -r count user; do
      echo "  $count attempts → user: $user"
    done

# ── Invalid user attempts (username + IP) ───────────────────────
echo -e "\n[+] INVALID USER ATTEMPTS (username + source IP):"
grep "Invalid user" "$LOGFILE" \
  | grep -oP 'Invalid user \K\S+ from \S+' \
  | sort | uniq -c | sort -rn | head -15 \
  | while read -r count info; do
      echo "  $count × $info"
    done

# ── Successful logins ───────────────────────────────────────────
echo -e "\n[+] SUCCESSFUL LOGINS (last 20):"
SUCCESSES=$(grep "Accepted password\|Accepted publickey" "$LOGFILE")
if [ -z "$SUCCESSES" ]; then
  echo "  None found"
else
  echo "$SUCCESSES" | tail -20 \
    | grep -oP '\d{4}-\d{2}-\d{2}T\S+ \S+ \S+: Accepted.*' \
    | while read -r line; do echo "  $line"; done
fi

# ── Sudo activity ───────────────────────────────────────────────
echo -e "\n[+] SUDO ACTIVITY (last 10 commands):"
SUDOS=$(grep "sudo" "$LOGFILE" | grep "COMMAND")
if [ -z "$SUDOS" ]; then
  echo "  None found"
else
  echo "$SUDOS" | tail -10 \
    | grep -oP '\d{4}-\d{2}-\d{2}T\S+.*' \
    | while read -r line; do echo "  $line"; done
fi

# ── Brute force timeline (top attacking IP hourly) ──────────────
TOP_IP=$(grep "Failed password" "$LOGFILE" | extract_ip \
  | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
if [ -n "$TOP_IP" ]; then
  echo -e "\n[+] ATTACK TIMELINE — Top IP: $TOP_IP (attempts per hour):"
  grep "Failed password" "$LOGFILE" | grep "$TOP_IP" \
    | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}' \
    | sort | uniq -c \
    | while read -r count hour; do
        bar=$(python3 -c "print('█' * min(int($count), 40))")
        echo "  $hour:xx  [$count]  $bar"
      done
fi

# ── Summary ─────────────────────────────────────────────────────
echo -e "\n[+] SUMMARY STATS:"
FAILED=$(grep -c 'Failed password' "$LOGFILE" 2>/dev/null || echo 0)
INVALID=$(grep -c 'Invalid user' "$LOGFILE" 2>/dev/null || echo 0)
SUCCESS=$(grep -c 'Accepted' "$LOGFILE" 2>/dev/null || echo 0)
UNIQUE=$(grep 'Failed password' "$LOGFILE" | extract_ip \
  | grep -E '^[0-9a-fA-F:.]' | sort -u | wc -l)
echo "  Total failed password attempts : $FAILED"
echo "  Total invalid user probes      : $INVALID"
echo "  Total successful logins        : $SUCCESS"
echo "  Unique attacking IPs           : $UNIQUE"
[ "$UNIQUE" -ge 1 ] && echo -e "\n  ${RED}⚠ Brute force activity detected — review attacking IPs above${RESET}"
echo "============================================"
} | tee "$REPORT"

echo -e "\n${GREEN}[*] Report saved to: $REPORT${RESET}"
EOF

# ══════════════════════════════════════════════════════════════════
# log_monitor.sh  (v2 — richer report with context lines)
# ══════════════════════════════════════════════════════════════════
section "Writing log_monitor.sh"
cat > "$SCRIPT_DIR/log_monitor.sh" << 'EOF'
#!/bin/bash
# ================================================================
#  log_monitor.sh  v2 — Full security keyword analysis
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
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
mkdir -p "$REPORT_DIR"

{
echo "========================================================"
echo "  Log Health Monitor Report"
echo "  Generated : $(date)"
echo "  System    : $(hostname)"
echo "  User      : $(whoami)"
echo "========================================================"

TOTAL_ISSUES=0

for log in "${LOGS[@]}"; do
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if [ ! -f "$log" ]; then
    echo "  LOG FILE : $log"
    echo "  STATUS   : NOT FOUND — skipping"
    continue
  fi

  SIZE=$(du -sh "$log" 2>/dev/null | cut -f1)
  LINES=$(wc -l < "$log" 2>/dev/null)
  MODIFIED=$(stat -c "%y" "$log" 2>/dev/null | cut -d'.' -f1)
  echo "  LOG FILE : $log"
  echo "  SIZE     : $SIZE  |  LINES: $LINES  |  MODIFIED: $MODIFIED"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  FILE_ISSUES=0
  for keyword in "${KEYWORDS[@]}"; do
    count=$(grep -ic "$keyword" "$log" 2>/dev/null || echo 0)
    if [ "$count" -gt 0 ]; then
      # Severity label
      case "$keyword" in
        critical|attack)       label="[CRITICAL]" ;;
        error|failed|denied)   label="[HIGH]    " ;;
        invalid|unauthorized)  label="[MEDIUM]  " ;;
        *)                     label="[LOW]     " ;;
      esac
      printf "  %s  %-15s : %d occurrences\n" "$label" "$keyword" "$count"
      FILE_ISSUES=$((FILE_ISSUES + count))
    fi
  done

  [ "$FILE_ISSUES" -eq 0 ] && echo "  [CLEAN]  No security keywords found" \
    || echo ""

  # Recent critical/error lines (last 5) for auth.log and syslog
  if [ "$log" = "/var/log/auth.log" ] && [ "$FILE_ISSUES" -gt 0 ]; then
    echo "  Recent auth events (last 5 security lines):"
    grep -iE "failed|invalid|error|denied|attack" "$log" 2>/dev/null \
      | tail -5 | sed 's/^/    /'
  fi

  TOTAL_ISSUES=$((TOTAL_ISSUES + FILE_ISSUES))
done

echo ""
echo "========================================================"
echo "  OVERALL SUMMARY"
echo "========================================================"
echo "  Total security keyword occurrences : $TOTAL_ISSUES"

# Risk rating
if [ "$TOTAL_ISSUES" -gt 5000 ]; then
  echo "  Risk Level : ⚠⚠⚠  HIGH — Immediate review recommended"
elif [ "$TOTAL_ISSUES" -gt 1000 ]; then
  echo "  Risk Level : ⚠⚠   MEDIUM — Review logs soon"
elif [ "$TOTAL_ISSUES" -gt 0 ]; then
  echo "  Risk Level : ⚠    LOW — Monitor closely"
else
  echo "  Risk Level : ✔    CLEAN — No issues found"
fi
echo "  Report saved to : $REPORT"
echo "========================================================"
} | tee "$REPORT"

echo -e "\n${GREEN}[*] Report saved: $REPORT${RESET}"
EOF

# ══════════════════════════════════════════════════════════════════
# siem_status.sh  (v2)
# ══════════════════════════════════════════════════════════════════
section "Writing siem_status.sh"
cat > "$SCRIPT_DIR/siem_status.sh" << 'EOF'
#!/bin/bash
# ================================================================
#  siem_status.sh  v2 — Full SIEM stack health check
#  Author : RH Vitharana | SLIIT — BSc (Hons) IT (Cyber Security)
#  Usage  : sudo bash siem_status.sh
# ================================================================

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
HOST_IP=$(hostname -I | awk '{print $1}')

echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   SIEM Stack — Service Status           ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  Time   : $(date)"
echo -e "  System : $(hostname)  |  IP: $HOST_IP"
echo ""

# ── Services ─────────────────────────────────────────────────────
echo -e "${BOLD}[1] Service Health:${RESET}"
ALL_GOOD=true
for svc in elasticsearch kibana logstash; do
  STATUS=$(systemctl is-active "$svc" 2>/dev/null)
  UPTIME=$(systemctl show "$svc" --property=ActiveEnterTimestamp 2>/dev/null \
    | cut -d= -f2 | sed 's/^ //')
  if [ "$STATUS" = "active" ]; then
    echo -e "  ${GREEN}[✔]${RESET} $svc — RUNNING  (since: $UPTIME)"
  else
    echo -e "  ${RED}[✘]${RESET} $svc — $STATUS"
    ALL_GOOD=false
  fi
done

# ── Elasticsearch ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[2] Elasticsearch Cluster:${RESET}"
ES_RESP=$(curl -s --max-time 5 http://localhost:9200 2>/dev/null)
if [ -n "$ES_RESP" ]; then
  CLUSTER=$(echo "$ES_RESP" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('cluster_name','?'))" 2>/dev/null)
  VERSION=$(echo "$ES_RESP" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['version']['number'])" 2>/dev/null)
  echo -e "  ${GREEN}[✔]${RESET} Cluster : $CLUSTER  |  Version: $VERSION"
  echo -e "  ${GREEN}[✔]${RESET} API     : http://localhost:9200"
else
  echo -e "  ${RED}[✘]${RESET} Elasticsearch API not responding"
fi

# ── Indices ───────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[3] Auth Log Indices:${RESET}"
IDX=$(curl -s --max-time 5 \
  "http://localhost:9200/_cat/indices/auth-logs-*?h=index,docs.count,store.size&s=index" 2>/dev/null)
if [ -n "$IDX" ]; then
  echo "$IDX" | while read -r line; do
    docs=$(echo "$line" | awk '{print $2}')
    echo -e "  ${GREEN}[✔]${RESET} $line"
  done
else
  echo -e "  ${YELLOW}[!]${RESET} No auth-logs-* indices yet"
  echo -e "  ${YELLOW}[i]${RESET} Logstash may still be ingesting — wait 60s and retry"
fi

# ── Reports ───────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[4] Recent Reports:${RESET}"
RDIR="/opt/siem-project/reports"
if [ -d "$RDIR" ] && ls "$RDIR"/*.txt &>/dev/null 2>&1; then
  ls -t "$RDIR"/*.txt | head -5 | while read -r f; do
    SIZE=$(du -sh "$f" 2>/dev/null | cut -f1)
    echo -e "  📄  $(basename "$f")  ($SIZE)"
  done
else
  echo -e "  ${YELLOW}[!]${RESET} No reports generated yet"
fi

# ── Cron jobs ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[5] Cron Jobs:${RESET}"
CRONF="/etc/cron.d/siem-project"
if [ -f "$CRONF" ]; then
  grep -v "^#\|^$" "$CRONF" | while read -r line; do
    echo -e "  ⏱  $line"
  done
else
  echo -e "  ${YELLOW}[!]${RESET} No cron file at $CRONF"
fi

# ── Access ────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[6] Access Points:${RESET}"
echo -e "  🌐  Kibana         : ${CYAN}http://${HOST_IP}:5601/app/dashboards${RESET}"
echo -e "  🔌  Elasticsearch  : ${CYAN}http://${HOST_IP}:9200${RESET}"

echo ""
if $ALL_GOOD; then
  echo -e "${GREEN}${BOLD}  ✔ All SIEM services running normally${RESET}"
else
  echo -e "${YELLOW}${BOLD}  ⚠ Some services need attention — see above${RESET}"
fi
echo ""
EOF

# ── Make all scripts executable ───────────────────────────────────
chmod +x "$SCRIPT_DIR"/*.sh
chown -R root:root "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"
log "Scripts installed and made executable in $SCRIPT_DIR"

# ── Cron jobs ─────────────────────────────────────────────────────
section "Installing Cron Jobs"
CRON_FILE="/etc/cron.d/siem-project"
cat > "$CRON_FILE" << EOF
# SIEM Project — Automated Monitoring
# Author: RH Vitharana | SLIIT

# SSH brute force scan — every hour
0 * * * * root $SCRIPT_DIR/ssh_bruteforce.sh >> $LOG_DIR/cron_ssh.log 2>&1

# Log health monitor — daily at 08:00
0 8 * * * root $SCRIPT_DIR/log_monitor.sh >> $LOG_DIR/cron_health.log 2>&1

# SIEM service status — every 30 minutes
*/30 * * * * root $SCRIPT_DIR/siem_status.sh >> $LOG_DIR/cron_status.log 2>&1
EOF
chmod 644 "$CRON_FILE"
log "Cron jobs installed at $CRON_FILE"

# ── Firewall ──────────────────────────────────────────────────────
section "Firewall"
if command -v ufw &>/dev/null; then
  ufw allow 5601/tcp comment "Kibana SIEM" >> "$SETUP_LOG" 2>&1
  ufw allow 9200/tcp comment "Elasticsearch" >> "$SETUP_LOG" 2>&1
  log "UFW rules added for ports 5601 and 9200"
else
  warn "UFW not found — skipping firewall"
fi

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   Scripts + Cron installed ✔            ║"
echo "  ║   Next: sudo bash 04_setup_kibana.sh    ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"
echo "  Scripts  : $SCRIPT_DIR"
echo "  Reports  : $REPORT_DIR"
echo "  Cron     : $CRON_FILE"
echo ""
echo -e "  Quick test: ${CYAN}sudo bash $SCRIPT_DIR/siem_status.sh${RESET}"
