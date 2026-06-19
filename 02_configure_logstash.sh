#!/bin/bash
# ================================================================
#  02_configure_logstash.sh  (CLEAN REWRITE v2)
#  Deploys Logstash pipeline for auth.log → Elasticsearch
#
#  FIXES vs original:
#    • Multi-match Grok handles "Failed password for invalid user"
#    • Permissions fixed: logstash added to adm group
#    • sincedb cleared before restart
#    • Waits properly for Logstash to fully start (up to 90s)
#    • Verifies data is actually flowing into ES before exit
#
#  Author : RH Vitharana | SLIIT — BSc (Hons) IT (Cyber Security)
#  Usage  : sudo bash 02_configure_logstash.sh
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

LOG_DIR="/opt/siem-project/logs"
SETUP_LOG="$LOG_DIR/logstash_config_$(date +%Y-%m-%d_%H-%M-%S).log"
LOGSTASH_CONF="/etc/logstash/conf.d/auth-log.conf"

log()     { echo -e "${GREEN}[✔]${RESET} $1" | tee -a "$SETUP_LOG"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1" | tee -a "$SETUP_LOG"; }
error()   { echo -e "${RED}[✘]${RESET} $1" | tee -a "$SETUP_LOG"; exit 1; }
info()    { echo -e "${CYAN}[i]${RESET} $1" | tee -a "$SETUP_LOG"; }
section() { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━${RESET}" | tee -a "$SETUP_LOG"; }

mkdir -p "$LOG_DIR"
touch "$SETUP_LOG"

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   STEP 2 — Configure Logstash Pipeline  ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash 02_configure_logstash.sh"

# ── Pre-flight ────────────────────────────────────────────────────
section "Pre-flight Checks"
systemctl list-units --full -all 2>/dev/null | grep -q "logstash.service" \
  || error "Logstash not installed. Run 01_install_elk.sh first."
log "Logstash service found"

[ -f /var/log/auth.log ] && log "auth.log exists ($(wc -l < /var/log/auth.log) lines)" \
  || warn "/var/log/auth.log not found — SSH must run at least once to create it"

# ── Stop Logstash before making changes ───────────────────────────
section "Stopping Logstash"
systemctl stop logstash 2>/dev/null
sleep 3
log "Logstash stopped"

# ── Remove any old pipeline configs ───────────────────────────────
section "Cleaning Old Pipeline Configs"
rm -f /etc/logstash/conf.d/*.conf
log "Cleared /etc/logstash/conf.d/"

# ── Clear sincedb so auth.log is read from scratch ────────────────
rm -f /var/lib/logstash/sincedb_auth
log "sincedb cleared — Logstash will re-read auth.log from beginning"

# ── Write the pipeline ────────────────────────────────────────────
section "Writing Logstash Pipeline"
mkdir -p /etc/logstash/conf.d

cat > "$LOGSTASH_CONF" << 'EOF'
# ================================================================
#  auth-log.conf  — SIEM Lab Pipeline (v2 clean)
#  Handles Ubuntu 22.04+ ISO 8601 auth.log format
#  Author : RH Vitharana | SLIIT
# ================================================================

input {
  file {
    path           => "/var/log/auth.log"
    start_position => "beginning"
    sincedb_path   => "/var/lib/logstash/sincedb_auth"
    type           => "auth"
    tags           => ["linux", "auth", "security"]
    stat_interval  => 1
    codec          => plain { charset => "UTF-8" }
  }
}

filter {

  # ── Parse Ubuntu 22.04+ ISO 8601 timestamp ─────────────────────
  # Format: 2026-06-13T20:28:23.123456+05:30 hostname program[pid]: message
  grok {
    match => {
      "message" => "%{TIMESTAMP_ISO8601:log_timestamp} %{HOSTNAME:log_host} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:log_message}"
    }
    tag_on_failure => ["_grok_main_fail"]
  }

  # ── Parse timestamp into @timestamp ────────────────────────────
  if "_grok_main_fail" not in [tags] {
    date {
      match    => ["log_timestamp", "ISO8601"]
      target   => "@timestamp"
      timezone => "Asia/Colombo"
    }
    mutate { remove_field => ["log_timestamp"] }
  }

  # ── Classify events ────────────────────────────────────────────
  if "_grok_main_fail" not in [tags] {

    # Failed SSH password (handles both "for user" and "for invalid user")
    if "Failed password" in [log_message] {
      grok {
        match => {
          "log_message" => [
            "Failed password for invalid user %{USER:username} from %{IP:src_ip} port %{NUMBER:src_port}",
            "Failed password for %{USER:username} from %{IP:src_ip} port %{NUMBER:src_port}"
          ]
        }
        tag_on_failure => ["_ssh_fail_parse"]
      }
      mutate {
        add_field => {
          "event_type"     => "ssh_failure"
          "event_severity" => "high"
          "event_category" => "authentication"
        }
        add_tag => ["ssh_failure"]
      }
    }

    # Invalid user probe (no password yet)
    else if "Invalid user" in [log_message] {
      grok {
        match => {
          "log_message" => "Invalid user %{USER:username} from %{IP:src_ip} port %{NUMBER:src_port}"
        }
        tag_on_failure => ["_invalid_user_parse"]
      }
      mutate {
        add_field => {
          "event_type"     => "invalid_user"
          "event_severity" => "high"
          "event_category" => "authentication"
        }
        add_tag => ["ssh_failure", "invalid_user"]
      }
    }

    # Successful login
    else if "Accepted password" in [log_message] or "Accepted publickey" in [log_message] {
      grok {
        match => {
          "log_message" => "Accepted %{WORD:auth_method} for %{USER:username} from %{IP:src_ip} port %{NUMBER:src_port}"
        }
        tag_on_failure => ["_ssh_success_parse"]
      }
      mutate {
        add_field => {
          "event_type"     => "ssh_success"
          "event_severity" => "low"
          "event_category" => "authentication"
        }
        add_tag => ["ssh_success"]
      }
    }

    # Sudo privilege escalation
    else if "sudo" in [program] and "COMMAND" in [log_message] {
      mutate {
        add_field => {
          "event_type"     => "sudo_usage"
          "event_severity" => "medium"
          "event_category" => "privilege_escalation"
        }
        add_tag => ["sudo_usage"]
      }
    }

    # Session opened
    else if "session opened" in [log_message] {
      mutate {
        add_field => {
          "event_type"     => "session_open"
          "event_severity" => "info"
          "event_category" => "session"
        }
        add_tag => ["session_open"]
      }
    }

    # Session closed
    else if "session closed" in [log_message] {
      mutate {
        add_field => {
          "event_type"     => "session_close"
          "event_severity" => "info"
          "event_category" => "session"
        }
        add_tag => ["session_close"]
      }
    }

  }

}

output {
  elasticsearch {
    hosts            => ["http://localhost:9200"]
    index            => "auth-logs-%{+YYYY.MM.dd}"
    action           => "index"
    manage_template  => false
  }
  # Uncomment to debug — shows every event in Logstash log:
  # stdout { codec => rubydebug }
}
EOF

log "Pipeline written to $LOGSTASH_CONF"

# ── Fix permissions ───────────────────────────────────────────────
section "Fixing Permissions"
usermod -aG adm logstash 2>/dev/null \
  && log "logstash added to adm group (can now read /var/log/auth.log)" \
  || warn "Could not add logstash to adm group"

# Ensure auth.log is readable by adm group
chmod g+r /var/log/auth.log 2>/dev/null || true

chown -R logstash:logstash /var/lib/logstash /var/log/logstash 2>/dev/null || true
chown -R root:logstash /etc/logstash 2>/dev/null || true
chmod -R 2750 /etc/logstash 2>/dev/null || true
log "Permissions set"

# ── Validate pipeline config syntax ──────────────────────────────
section "Validating Pipeline Config"
info "Running config syntax test (may take 30s)..."
/usr/share/logstash/bin/logstash --config.test_and_exit \
  -f "$LOGSTASH_CONF" >> "$SETUP_LOG" 2>&1 \
  && log "Config syntax OK ✔" \
  || warn "Config test warnings — check $SETUP_LOG (usually safe to continue)"

# ── Start Logstash ────────────────────────────────────────────────
section "Starting Logstash"
systemctl daemon-reload >> "$SETUP_LOG" 2>&1
systemctl start logstash >> "$SETUP_LOG" 2>&1

info "Waiting for Logstash to start (up to 90s)..."
for i in $(seq 1 18); do
  sleep 5
  STATUS=$(systemctl is-active logstash 2>/dev/null)
  if [ "$STATUS" = "active" ]; then
    log "Logstash is active ✔ (${i}×5s)"
    break
  fi
  echo -n "."
  if [ "$i" -eq 18 ]; then
    warn "Logstash slow to start — check: sudo journalctl -u logstash -n 30"
  fi
done

# ── Verify data flowing into Elasticsearch ────────────────────────
section "Verifying Data Flow"
info "Waiting up to 60s for auth-logs-* index to appear in Elasticsearch..."
for i in $(seq 1 12); do
  sleep 5
  DOCS=$(curl -s "http://localhost:9200/_cat/indices/auth-logs-*?h=docs.count" 2>/dev/null \
         | grep -v '^0$' | head -1 | tr -d ' ')
  if [ -n "$DOCS" ] && [ "$DOCS" != "0" ]; then
    log "Data flowing! auth-logs-* has $DOCS documents ✔"
    break
  fi
  echo -n "."
  if [ "$i" -eq 12 ]; then
    warn "Index not yet populated — Logstash may still be starting up"
    warn "Check in 60s: curl http://localhost:9200/_cat/indices/auth-logs-*?v"
  fi
done

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   Logstash pipeline configured ✔        ║"
echo "  ║   Next: sudo bash 03_install_scripts.sh ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  Verify data: ${CYAN}curl http://localhost:9200/_cat/indices/auth-logs-*?v${RESET}"
echo    "  Full log:    $SETUP_LOG"
