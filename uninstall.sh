#!/bin/bash
# ================================================================
#  uninstall.sh — SIEM Project Uninstaller
#  Removes everything installed by steps 02, 03, 04:
#
#    STEP 02 — Logstash pipeline config + sincedb
#    STEP 03 — SIEM scripts, reports, logs, cron jobs
#    STEP 04 — Kibana visualizations, dashboard, data view
#            — Elasticsearch auth-logs-* indices
#
#  Does NOT touch:
#    ✘  Elasticsearch (service + install)
#    ✘  Kibana (service + install)
#    ✘  Logstash (service + install)
#    ✘  Java
#    ✘  Any apt packages
#    (i.e. step 01 is kept intact)
#
#  Author : RH Vitharana | SLIIT — BSc (Hons) IT (Cyber Security)
#  Usage  : sudo bash uninstall.sh
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

KB="http://localhost:5601"
ES="http://localhost:9200"

ok()      { echo -e "  ${GREEN}[✔]${RESET} $1"; }
skip()    { echo -e "  ${YELLOW}[~]${RESET} $1 (not found — skipping)"; }
fail()    { echo -e "  ${RED}[✘]${RESET} $1"; }
info()    { echo -e "  ${CYAN}[i]${RESET} $1"; }
section() { echo -e "\n${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}";
            echo -e "${BOLD}${BLUE}  $1${RESET}";
            echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

# ── Root check ────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && echo -e "${RED}[✘] Run as root: sudo bash uninstall.sh${RESET}" && exit 1

# ── Banner ────────────────────────────────────────────────────────
clear
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║   SIEM Project — Uninstaller                            ║"
echo "  ║   Removes: Steps 02 + 03 + 04                          ║"
echo "  ║   Keeps  : Step 01 (ELK Stack install)                 ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Show what will be removed ─────────────────────────────────────
echo -e "${BOLD}  The following will be permanently removed:${RESET}"
echo ""
echo -e "  ${YELLOW}STEP 02 — Logstash Pipeline${RESET}"
echo "    • /etc/logstash/conf.d/auth-log.conf"
echo "    • /var/lib/logstash/sincedb_auth"
echo ""
echo -e "  ${YELLOW}STEP 03 — SIEM Scripts + Automation${RESET}"
echo "    • /opt/siem-project/scripts/  (ssh_bruteforce, log_monitor, siem_status)"
echo "    • /opt/siem-project/reports/  (all generated reports)"
echo "    • /opt/siem-project/logs/     (all install + cron logs)"
echo "    • /etc/cron.d/siem-project    (all scheduled jobs)"
echo ""
echo -e "  ${YELLOW}STEP 04 — Kibana + Elasticsearch Data${RESET}"
echo "    • Kibana: all auth-logs visualizations"
echo "    • Kibana: Linux Security Monitoring Dashboard"
echo "    • Kibana: auth-logs-* Data View"
echo "    • Elasticsearch: all auth-logs-* indices (your log data)"
echo ""
echo -e "  ${GREEN}KEPT (Step 01):${RESET}"
echo "    • Elasticsearch service + installation"
echo "    • Kibana service + installation"
echo "    • Logstash service + installation"
echo "    • Java"
echo ""

# ── Confirm ───────────────────────────────────────────────────────
read -rp "  Type YES to confirm uninstall: " CONFIRM
if [ "$CONFIRM" != "YES" ]; then
  echo -e "\n${CYAN}  Cancelled — nothing was changed.${RESET}\n"
  exit 0
fi

echo ""
START_TIME=$(date +%s)

# ══════════════════════════════════════════════════════════════════
# STEP 02 — Remove Logstash pipeline
# ══════════════════════════════════════════════════════════════════
section "STEP 02 — Logstash Pipeline"

# Stop Logstash cleanly before touching its config
info "Stopping Logstash..."
systemctl stop logstash 2>/dev/null
sleep 3
STATUS=$(systemctl is-active logstash 2>/dev/null)
[ "$STATUS" != "active" ] && ok "Logstash stopped" || info "Logstash still running (will reload with no pipeline)"

# Remove all pipeline configs belonging to this project
REMOVED_CONF=0
for conf_file in /etc/logstash/conf.d/auth-log*.conf /etc/logstash/conf.d/auth-log.conf; do
  if [ -f "$conf_file" ]; then
    rm -f "$conf_file"
    ok "Removed pipeline config: $conf_file"
    REMOVED_CONF=$((REMOVED_CONF + 1))
  fi
done
[ "$REMOVED_CONF" -eq 0 ] && skip "No auth-log*.conf pipeline configs found"

# Remove sincedb — so a reinstall reads auth.log from scratch
SINCEDB="/var/lib/logstash/sincedb_auth"
if [ -f "$SINCEDB" ]; then
  rm -f "$SINCEDB"
  ok "Removed sincedb: $SINCEDB"
else
  skip "sincedb: $SINCEDB"
fi

# Restart Logstash with no pipeline (clean idle state)
info "Restarting Logstash (no pipeline — idle state)..."
systemctl start logstash 2>/dev/null
sleep 4
STATUS=$(systemctl is-active logstash 2>/dev/null)
[ "$STATUS" = "active" ] \
  && ok "Logstash running (idle — no pipeline loaded)" \
  || info "Logstash status: $STATUS (OK if no pipeline config)"

# ══════════════════════════════════════════════════════════════════
# STEP 03 — Remove SIEM scripts, reports, logs, cron
# ══════════════════════════════════════════════════════════════════
section "STEP 03 — SIEM Scripts + Cron Jobs"

INSTALL_DIR="/opt/siem-project"

# Scripts
if [ -d "$INSTALL_DIR/scripts" ]; then
  rm -rf "$INSTALL_DIR/scripts"
  ok "Removed scripts dir: $INSTALL_DIR/scripts"
else
  skip "Scripts dir: $INSTALL_DIR/scripts"
fi

# Reports
if [ -d "$INSTALL_DIR/reports" ]; then
  REPORT_COUNT=$(find "$INSTALL_DIR/reports" -name "*.txt" 2>/dev/null | wc -l)
  rm -rf "$INSTALL_DIR/reports"
  ok "Removed reports dir: $INSTALL_DIR/reports ($REPORT_COUNT report files)"
else
  skip "Reports dir: $INSTALL_DIR/reports"
fi

# Logs
if [ -d "$INSTALL_DIR/logs" ]; then
  LOG_COUNT=$(find "$INSTALL_DIR/logs" -name "*.log" 2>/dev/null | wc -l)
  rm -rf "$INSTALL_DIR/logs"
  ok "Removed logs dir: $INSTALL_DIR/logs ($LOG_COUNT log files)"
else
  skip "Logs dir: $INSTALL_DIR/logs"
fi

# Remove parent dir only if now empty
if [ -d "$INSTALL_DIR" ]; then
  REMAINING=$(ls -A "$INSTALL_DIR" 2>/dev/null | wc -l)
  if [ "$REMAINING" -eq 0 ]; then
    rmdir "$INSTALL_DIR"
    ok "Removed empty parent dir: $INSTALL_DIR"
  else
    info "Keeping $INSTALL_DIR (still has other files):"
    ls "$INSTALL_DIR" | sed 's/^/      /'
  fi
fi

# Cron jobs
CRON_FILE="/etc/cron.d/siem-project"
if [ -f "$CRON_FILE" ]; then
  rm -f "$CRON_FILE"
  ok "Removed cron file: $CRON_FILE"
else
  skip "Cron file: $CRON_FILE"
fi

# ══════════════════════════════════════════════════════════════════
# STEP 04 — Remove Kibana objects + Elasticsearch indices
# ══════════════════════════════════════════════════════════════════
section "STEP 04 — Kibana Objects + Elasticsearch Indices"

# ── 4a. Kibana ────────────────────────────────────────────────────
info "Checking Kibana availability..."
KB_UP=false
for i in $(seq 1 12); do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$KB/api/status" 2>/dev/null)
  if [ "$CODE" = "200" ]; then KB_UP=true; break; fi
  echo -n "."; sleep 5
done
[ "$KB_UP" = "false" ] && echo ""

if $KB_UP; then
  ok "Kibana is up — proceeding with cleanup"

  # Helper: get saved object ID by exact title match
  get_kibana_id() {
    local type="$1" title="$2"
    local encoded
    encoded=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$title" 2>/dev/null)
    curl -s "$KB/api/saved_objects/_find?type=$type&search_fields=title&search=$encoded&per_page=50" \
      -H "kbn-xsrf: true" 2>/dev/null \
      | python3 -c "
import sys,json
title=sys.argv[1]
try:
  d=json.load(sys.stdin)
  for o in d.get('saved_objects',[]):
    if o.get('attributes',{}).get('title')==title:
      print(o['id']); break
except: pass
" "$title" 2>/dev/null
  }

  # Helper: delete saved object
  delete_kibana_object() {
    local type="$1" title="$2" id="$3"
    if [ -n "$id" ]; then
      CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X DELETE "$KB/api/saved_objects/$type/$id" \
        -H "kbn-xsrf: true" 2>/dev/null)
      ok "Deleted $type: '$title' (HTTP $CODE)"
    else
      skip "$type: '$title'"
    fi
  }

  # Delete dashboard
  DASH_ID=$(get_kibana_id "dashboard" "Linux Security Monitoring Dashboard")
  delete_kibana_object "dashboard" "Linux Security Monitoring Dashboard" "$DASH_ID"

  # Delete all visualizations
  VIZ_TITLES=(
    "Failed SSH Logins Over Time"
    "Top Attacking IPs"
    "Security Event Types"
    "Failed Logins Today"
    "SSH Brute Force Report — Top IPs & Users"
    "Log Health Report — Event Severity Breakdown"
  )
  for title in "${VIZ_TITLES[@]}"; do
    id=$(get_kibana_id "visualization" "$title")
    delete_kibana_object "visualization" "$title" "$id"
  done

  # Delete Data View
  DV_ID=$(curl -s "$KB/api/data_views" -H "kbn-xsrf: true" 2>/dev/null \
    | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  for v in d.get('data_view',[]):
    if 'auth-logs' in v.get('title',''):
      print(v.get('id','')); break
except: pass
" 2>/dev/null)

  if [ -n "$DV_ID" ]; then
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      -X DELETE "$KB/api/data_views/data_view/$DV_ID" \
      -H "kbn-xsrf: true" 2>/dev/null)
    ok "Deleted Data View: auth-logs-* (HTTP $CODE)"
  else
    skip "Data View: auth-logs-*"
  fi

else
  echo ""
  fail "Kibana not responding — skipping Kibana cleanup"
  info "To clean Kibana manually later, start Kibana then re-run:"
  info "  sudo bash uninstall.sh"
fi

# ── 4b. Elasticsearch indices ─────────────────────────────────────
info "Checking Elasticsearch availability..."
ES_UP=false
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$ES" 2>/dev/null)
[ "$CODE" = "200" ] && ES_UP=true

if $ES_UP; then
  ok "Elasticsearch is up — removing auth-logs-* indices"
  INDICES=$(curl -s --max-time 5 "$ES/_cat/indices/auth-logs-*?h=index" 2>/dev/null)
  if [ -n "$INDICES" ]; then
    INDEX_COUNT=0
    while IFS= read -r idx; do
      [ -z "$idx" ] && continue
      CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X DELETE "$ES/$idx" 2>/dev/null)
      ok "Deleted index: $idx (HTTP $CODE)"
      INDEX_COUNT=$((INDEX_COUNT + 1))
    done <<< "$INDICES"
    ok "Removed $INDEX_COUNT auth-logs-* index(es)"
  else
    skip "No auth-logs-* indices found in Elasticsearch"
  fi
else
  fail "Elasticsearch not responding — skipping index deletion"
  info "To delete indices manually later:"
  info "  curl -X DELETE http://localhost:9200/auth-logs-*"
fi

# ══════════════════════════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════════════════════════
END_TIME=$(date +%s)
TOTAL=$(( END_TIME - START_TIME ))
MINS=$(( TOTAL / 60 ))
SECS=$(( TOTAL % 60 ))

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║   Uninstall Complete ✔                                  ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  ${BOLD}Completed in:${RESET} ${MINS}m ${SECS}s"
echo -e "  ${BOLD}Finished at :${RESET} $(date)"
echo ""
echo -e "  ${BOLD}Removed (02):${RESET}"
echo "    ✔  Logstash pipeline config (auth-log.conf)"
echo "    ✔  Logstash sincedb"
echo ""
echo -e "  ${BOLD}Removed (03):${RESET}"
echo "    ✔  SIEM scripts (/opt/siem-project/scripts/)"
echo "    ✔  Generated reports (/opt/siem-project/reports/)"
echo "    ✔  Install + cron logs (/opt/siem-project/logs/)"
echo "    ✔  Cron jobs (/etc/cron.d/siem-project)"
echo ""
echo -e "  ${BOLD}Removed (04):${RESET}"
echo "    ✔  Kibana dashboard + visualizations + data view"
echo "    ✔  Elasticsearch auth-logs-* indices"
echo ""
echo -e "  ${BOLD}Kept (01 — ELK Stack):${RESET}"
echo "    •  Elasticsearch, Kibana, Logstash — services still running"
echo "    •  Java"
echo ""
echo -e "  ${BOLD}To reinstall cleanly:${RESET}"
echo -e "    ${CYAN}sudo bash run.sh${RESET}   (runs steps 01→04)"
echo -e "    ${CYAN}sudo bash 02_configure_logstash.sh${RESET}"
echo -e "    ${CYAN}sudo bash 03_install_scripts.sh${RESET}"
echo -e "    ${CYAN}sudo bash 04_setup_kibana.sh${RESET}"
