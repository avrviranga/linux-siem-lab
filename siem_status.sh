#!/bin/bash
# ================================================================
#  siem_status.sh
#  Checks the health of all SIEM stack services
#  Author : RH Vitharana | SLIIT — BSc (Hons) IT (Cyber Security)
#  Usage  : sudo bash siem_status.sh
# ================================================================

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

HOST_IP=$(hostname -I | awk '{print $1}')
SERVICES=("elasticsearch" "kibana" "logstash")

echo -e "${BOLD}========================================"
echo "  SIEM Stack — Service Status"
echo "  $(date)"
echo -e "========================================${RESET}"
echo ""

# ── Service Status ────────────────────────────────────────────────
echo -e "${BOLD}Services:${RESET}"
ALL_GOOD=true
for svc in "${SERVICES[@]}"; do
  STATUS=$(systemctl is-active "$svc" 2>/dev/null)
  if [ "$STATUS" = "active" ]; then
    echo -e "  ${GREEN}[✔]${RESET} $svc — RUNNING"
  else
    echo -e "  ${RED}[✘]${RESET} $svc — $STATUS"
    ALL_GOOD=false
  fi
done

# ── Elasticsearch Cluster Info ────────────────────────────────────
echo ""
echo -e "${BOLD}Elasticsearch Cluster:${RESET}"
ES_RESPONSE=$(curl -s http://localhost:9200 2>/dev/null)
if [ -n "$ES_RESPONSE" ]; then
  CLUSTER=$(echo "$ES_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('cluster_name','unknown'))" 2>/dev/null)
  VERSION=$(echo "$ES_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['version']['number'])" 2>/dev/null)
  echo -e "  ${GREEN}[✔]${RESET} Cluster : $CLUSTER"
  echo -e "  ${GREEN}[✔]${RESET} Version : $VERSION"
else
  echo -e "  ${RED}[✘]${RESET} Elasticsearch API not responding"
fi

# ── Index Status ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Log Indices in Elasticsearch:${RESET}"
INDEX_INFO=$(curl -s "http://localhost:9200/_cat/indices/auth-logs-*?h=index,docs.count,store.size&s=index" 2>/dev/null)
if [ -n "$INDEX_INFO" ]; then
  echo "$INDEX_INFO" | while read line; do
    echo "  📊  $line"
  done
else
  echo -e "  ${YELLOW}[!]${RESET} No auth-logs indices found yet (Logstash may still be ingesting)"
fi

# ── Access URLs ───────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Access Points:${RESET}"
echo -e "  🌐  Kibana Dashboard   : ${CYAN}http://${HOST_IP}:5601${RESET}"
echo -e "  🔌  Elasticsearch API  : ${CYAN}http://${HOST_IP}:9200${RESET}"

# ── Cron Jobs ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Scheduled Automation (Cron):${RESET}"
if [ -f /etc/cron.d/siem-project ]; then
  grep -v "^#\|^$" /etc/cron.d/siem-project | while read line; do
    echo "  ⏱  $line"
  done
else
  echo -e "  ${YELLOW}[!]${RESET} No cron jobs found"
fi

echo ""
echo "========================================"
if $ALL_GOOD; then
  echo -e "${GREEN}${BOLD}  All services running normally ✔${RESET}"
else
  echo -e "${YELLOW}${BOLD}  Some services need attention — check logs above${RESET}"
fi
echo "========================================"
