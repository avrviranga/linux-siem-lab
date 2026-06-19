#!/bin/bash
# ================================================================
#  01_install_elk.sh
#  Installs Java + ELK Stack (Elasticsearch, Kibana, Logstash)
#  Run this FIRST.
#  Author : RH Vitharana | SLIIT — BSc (Hons) IT (Cyber Security)
#  Usage  : sudo bash 01_install_elk.sh
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

LOG_DIR="/opt/siem-project/logs"
SETUP_LOG="$LOG_DIR/elk_install_$(date +%Y-%m-%d_%H-%M-%S).log"
ELK_VERSION="8.x"

log()     { echo -e "${GREEN}[✔]${RESET} $1" | tee -a "$SETUP_LOG"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1" | tee -a "$SETUP_LOG"; }
error()   { echo -e "${RED}[✘]${RESET} $1" | tee -a "$SETUP_LOG"; exit 1; }
info()    { echo -e "${CYAN}[i]${RESET} $1" | tee -a "$SETUP_LOG"; }
section() { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━${RESET}" | tee -a "$SETUP_LOG"; }

mkdir -p "$LOG_DIR"
touch "$SETUP_LOG"

# ── Root check ────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash 01_install_elk.sh"
log "Running as root"

# ── Internet check ────────────────────────────────────────────────
ping -c 1 -W 3 google.com &>/dev/null || error "No internet connection."
log "Internet OK"

# ── RAM check ─────────────────────────────────────────────────────
TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
[ "$TOTAL_RAM" -lt 3500 ] && warn "Low RAM (${TOTAL_RAM}MB) — ELK recommends 4 GB minimum"
log "RAM: ${TOTAL_RAM}MB"

# ── OS Detection ──────────────────────────────────────────────────
section "Detecting OS"
. /etc/os-release 2>/dev/null || error "Cannot read /etc/os-release"
case "$ID" in
  ubuntu|debian|kali) log "Detected: $NAME $VERSION_ID" ;;
  *) echo "$ID_LIKE" | grep -qiE "debian|ubuntu" \
       && warn "Treating '$NAME' as Debian-based" \
       || error "Unsupported OS: $NAME" ;;
esac

# ── System update + deps ───────────────────────────────────────────
section "Updating System Packages"
apt update -y >> "$SETUP_LOG" 2>&1 || error "apt update failed"
apt install -y curl wget gnupg2 apt-transport-https \
  software-properties-common net-tools lsb-release \
  >> "$SETUP_LOG" 2>&1 || error "Dependency install failed"
log "Dependencies installed"

# ── Java ──────────────────────────────────────────────────────────
section "Installing Java"
if java -version &>/dev/null 2>&1; then
  log "Java already installed: $(java -version 2>&1 | head -1)"
else
  apt install -y default-jdk >> "$SETUP_LOG" 2>&1
  java -version &>/dev/null 2>&1 || \
    apt install -y openjdk-17-jdk >> "$SETUP_LOG" 2>&1 || \
    apt install -y openjdk-11-jdk >> "$SETUP_LOG" 2>&1 || \
    error "Java installation failed"
  log "Java installed: $(java -version 2>&1 | head -1)"
fi

# ── Elastic Repository ────────────────────────────────────────────
section "Adding Elastic Repository"
KEYRING="/usr/share/keyrings/elasticsearch-keyring.gpg"
SOURCES="/etc/apt/sources.list.d/elastic-8.x.list"
if [ ! -f "$SOURCES" ]; then
  wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
    | gpg --dearmor -o "$KEYRING" >> "$SETUP_LOG" 2>&1 \
    || error "Failed to download Elastic GPG key"
  echo "deb [signed-by=$KEYRING] https://artifacts.elastic.co/packages/${ELK_VERSION}/apt stable main" \
    > "$SOURCES"
  apt update -y >> "$SETUP_LOG" 2>&1
  log "Elastic repository added"
else
  log "Elastic repository already configured"
fi

# ── Elasticsearch ─────────────────────────────────────────────────
section "Installing Elasticsearch"
if ! systemctl list-units --full -all 2>/dev/null | grep -q "elasticsearch.service"; then
  info "Installing elasticsearch (may take a few minutes)..."
  apt install -y elasticsearch >> "$SETUP_LOG" 2>&1 || error "Elasticsearch install failed"
  log "Elasticsearch installed"
else
  log "Elasticsearch already installed"
fi

info "Configuring Elasticsearch..."
ES_CONF="/etc/elasticsearch/elasticsearch.yml"
cp "$ES_CONF" "${ES_CONF}.backup" 2>/dev/null
cat > "$ES_CONF" <<'EOF'
cluster.name: siem-lab-cluster
node.name: siem-node-1
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
indices.memory.index_buffer_size: 10%
EOF

TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
HEAP_SIZE=$(( TOTAL_RAM / 4 ))
[ "$HEAP_SIZE" -gt 2048 ] && HEAP_SIZE=2048
[ "$HEAP_SIZE" -lt 512  ] && HEAP_SIZE=512
mkdir -p /etc/elasticsearch/jvm.options.d
printf -- "-Xms${HEAP_SIZE}m\n-Xmx${HEAP_SIZE}m\n" \
  > /etc/elasticsearch/jvm.options.d/heap.options
log "JVM heap: ${HEAP_SIZE}MB"

chown -R elasticsearch:elasticsearch /usr/share/elasticsearch /var/lib/elasticsearch /var/log/elasticsearch 2>/dev/null || true
chown -R root:elasticsearch /etc/elasticsearch 2>/dev/null || true
chmod -R 2750 /etc/elasticsearch 2>/dev/null || true

systemctl daemon-reload >> "$SETUP_LOG" 2>&1
systemctl enable elasticsearch >> "$SETUP_LOG" 2>&1
systemctl restart elasticsearch >> "$SETUP_LOG" 2>&1

info "Waiting for Elasticsearch (up to 120s)..."
for i in $(seq 1 24); do
  sleep 5
  curl -s http://localhost:9200 &>/dev/null && { log "Elasticsearch is up ✔"; break; }
  echo -n "."
  [ "$i" -eq 24 ] && { journalctl -u elasticsearch --no-pager -n 20; error "Elasticsearch failed to start"; }
done

# ── Kibana ────────────────────────────────────────────────────────
section "Installing Kibana"
if ! systemctl list-units --full -all 2>/dev/null | grep -q "kibana.service"; then
  apt install -y kibana >> "$SETUP_LOG" 2>&1 || error "Kibana install failed"
  log "Kibana installed"
else
  log "Kibana already installed"
fi

HOST_IP=$(hostname -I | awk '{print $1}')
KB_CONF="/etc/kibana/kibana.yml"
cp "$KB_CONF" "${KB_CONF}.backup" 2>/dev/null
cat > "$KB_CONF" <<EOF
server.port: 5601
server.host: "0.0.0.0"
server.name: "siem-lab-kibana"
elasticsearch.hosts: ["http://localhost:9200"]
logging.root.level: warn
EOF

systemctl daemon-reload >> "$SETUP_LOG" 2>&1
systemctl enable kibana >> "$SETUP_LOG" 2>&1
systemctl restart kibana >> "$SETUP_LOG" 2>&1
log "Kibana configured — http://${HOST_IP}:5601"

# ── Logstash ──────────────────────────────────────────────────────
section "Installing Logstash"
if ! systemctl list-units --full -all 2>/dev/null | grep -q "logstash.service"; then
  info "Installing logstash (may take a few minutes)..."
  apt install -y logstash >> "$SETUP_LOG" 2>&1 || error "Logstash install failed"
  log "Logstash installed"
else
  log "Logstash already installed"
fi

chown -R logstash:logstash /var/lib/logstash /var/log/logstash 2>/dev/null || true
chown -R root:logstash /etc/logstash 2>/dev/null || true
chmod -R 2750 /etc/logstash 2>/dev/null || true

systemctl daemon-reload >> "$SETUP_LOG" 2>&1
systemctl enable logstash >> "$SETUP_LOG" 2>&1

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   ELK Stack installed successfully ✔    ║"
echo "  ║                                          ║"
echo "  ║   Next: sudo bash 02_configure_logstash.sh ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"
echo "  Install log: $SETUP_LOG"
