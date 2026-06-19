#!/bin/bash
# ================================================================
#  siem_diagnose.sh
#  Diagnoses why data is not appearing in Kibana / Elasticsearch
#  Author : RH Vitharana | SLIIT — BSc (Hons) IT (Cyber Security)
#  Usage  : sudo bash siem_diagnose.sh
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}[✔]${RESET} $1"; }
fail() { echo -e "  ${RED}[✘]${RESET} $1"; }
warn() { echo -e "  ${YELLOW}[!]${RESET} $1"; }
info() { echo -e "  ${CYAN}[i]${RESET} $1"; }

echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   SIEM Diagnostic — Kibana No Data Fix  ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"

# ── 1. Service status ─────────────────────────────────────────────
echo -e "${BOLD}[1] Service Status${RESET}"
for svc in elasticsearch kibana logstash; do
  STATUS=$(systemctl is-active "$svc" 2>/dev/null)
  [ "$STATUS" = "active" ] && ok "$svc: RUNNING" || fail "$svc: $STATUS"
done

# ── 2. Elasticsearch responding? ──────────────────────────────────
echo -e "\n${BOLD}[2] Elasticsearch API${RESET}"
ES=$(curl -s http://localhost:9200 2>/dev/null)
if [ -n "$ES" ]; then
  ok "Elasticsearch responding"
  VER=$(echo "$ES" | python3 -c "import sys,json;print(json.load(sys.stdin)['version']['number'])" 2>/dev/null)
  info "Version: $VER"
else
  fail "Elasticsearch not responding on port 9200"
fi

# ── 3. auth-logs indices ──────────────────────────────────────────
echo -e "\n${BOLD}[3] Elasticsearch Indices${RESET}"
INDICES=$(curl -s "http://localhost:9200/_cat/indices/auth-logs-*?v" 2>/dev/null)
if [ -n "$INDICES" ]; then
  ok "auth-logs-* indices found:"
  echo "$INDICES" | sed 's/^/    /'
else
  fail "No auth-logs-* indices found — Logstash has not ingested any data yet"
  warn "→ This is likely the main reason Kibana shows nothing"
fi

# ── 4. Logstash sincedb ───────────────────────────────────────────
echo -e "\n${BOLD}[4] Logstash sincedb${RESET}"
SINCEDB="/var/lib/logstash/sincedb_auth"
if [ -f "$SINCEDB" ]; then
  info "sincedb exists: $SINCEDB"
  info "Content: $(cat $SINCEDB)"
  warn "If Logstash already read auth.log once but failed to push to ES,"
  warn "clear it with:  sudo rm -f $SINCEDB && sudo systemctl restart logstash"
else
  ok "sincedb not present — Logstash will read auth.log from beginning"
fi

# ── 5. auth.log readability ───────────────────────────────────────
echo -e "\n${BOLD}[5] auth.log Access${RESET}"
AUTH="/var/log/auth.log"
if [ ! -f "$AUTH" ]; then
  fail "$AUTH does not exist"
elif [ ! -r "$AUTH" ]; then
  fail "$AUTH exists but is NOT readable by current user"
  warn "→ Fix with:  sudo usermod -aG adm logstash && sudo systemctl restart logstash"
else
  ok "$AUTH is readable"
  LINES=$(wc -l < "$AUTH")
  info "Lines in auth.log: $LINES"
  info "Last 3 lines:"
  tail -3 "$AUTH" | sed 's/^/    /'
fi

# ── 6. Logstash pipeline config ───────────────────────────────────
echo -e "\n${BOLD}[6] Logstash Pipeline Config${RESET}"
CONF="/etc/logstash/conf.d/auth-log.conf"
if [ -f "$CONF" ]; then
  ok "Pipeline config found: $CONF"
  # Check if the new ISO8601 grok pattern is present
  if grep -q "TIMESTAMP_ISO8601" "$CONF"; then
    ok "ISO 8601 grok pattern detected (correct for Ubuntu 22.04+)"
  else
    fail "Old-style timestamp grok — may not match your log format"
    warn "→ Run: sudo bash 02_configure_logstash.sh"
  fi
  # Check for multi-match failed password pattern
  if grep -q "invalid user" "$CONF"; then
    ok "Multi-match Grok (handles 'invalid user') present"
  else
    warn "Single-match Grok only — run fix_top_attacking_ips.sh to fix"
  fi
else
  fail "No pipeline config at $CONF"
  warn "→ Run: sudo bash 02_configure_logstash.sh"
fi

# ── 7. Logstash recent logs ───────────────────────────────────────
echo -e "\n${BOLD}[7] Logstash Journal (last 20 lines)${RESET}"
journalctl -u logstash --no-pager -n 20 2>/dev/null | tail -20 | sed 's/^/  /'

# ── 8. Kibana Data View ───────────────────────────────────────────
echo -e "\n${BOLD}[8] Kibana Data View${RESET}"
DV=$(curl -s "http://localhost:5601/api/data_views" -H "kbn-xsrf: true" 2>/dev/null)
if echo "$DV" | grep -q "auth-logs"; then
  ok "auth-logs-* Data View exists in Kibana"
else
  warn "No auth-logs-* Data View found"
  warn "→ Run: sudo bash 04_setup_kibana.sh"
fi

# ── 9. Quick fix recommendations ─────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}━━━ Recommended Fix Order ━━━${RESET}"
echo "  1. sudo usermod -aG adm logstash"
echo "  2. sudo rm -f /var/lib/logstash/sincedb_auth"
echo "  3. sudo systemctl restart logstash"
echo "  4. Wait 60 seconds, then run:"
echo "     curl http://localhost:9200/_cat/indices/auth-logs-*?v"
echo "  5. If indices appear → sudo bash 04_setup_kibana.sh"
echo "  6. Open http://$(hostname -I | awk '{print $1}'):5601/app/dashboards"
echo ""
echo -e "${BOLD}${GREEN}━━━ Diagnosis Complete ━━━${RESET}"
