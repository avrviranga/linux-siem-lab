#!/bin/bash
# ================================================================
#  04_setup_kibana.sh  (CLEAN REWRITE v2)
#  Creates Kibana Data View + 6 visualizations + dashboard
#
#  VISUALIZATIONS:
#    1. Failed SSH Logins Over Time  (bar chart)
#    2. Top Attacking IPs            (pie — query: src_ip:*)
#    3. Security Event Types         (donut)
#    4. Failed Logins Today          (metric)
#    5. Log Health Report            (data table — keyword counts)
#    6. SSH Brute Force Report       (data table — top IPs + users)
#
#  FIXES vs original:
#    • Top Attacking IPs uses src_ip:* (not event_type filter)
#      so it correctly shows all IPs regardless of Grok variant
#    • Waits properly for Kibana (up to 3 min)
#    • Checks ES has data before creating dashboard
#    • Log Health + SSH Report tables added
#
#  Author : RH Vitharana | SLIIT — BSc (Hons) IT (Cyber Security)
#  Usage  : sudo bash 04_setup_kibana.sh
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

LOG_DIR="/opt/siem-project/logs"
SETUP_LOG="$LOG_DIR/kibana_setup_$(date +%Y-%m-%d_%H-%M-%S).log"
KB="http://localhost:5601"
ES="http://localhost:9200"
TMP=$(mktemp -d)

log()     { echo -e "${GREEN}[✔]${RESET} $1" | tee -a "$SETUP_LOG"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1" | tee -a "$SETUP_LOG"; }
error()   { echo -e "${RED}[✘]${RESET} $1" | tee -a "$SETUP_LOG"; rm -rf "$TMP"; exit 1; }
info()    { echo -e "${CYAN}[i]${RESET} $1" | tee -a "$SETUP_LOG"; }
section() { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━${RESET}" | tee -a "$SETUP_LOG"; }

mkdir -p "$LOG_DIR"
touch "$SETUP_LOG"

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash 04_setup_kibana.sh"

# ── Check Elasticsearch has data ─────────────────────────────────
section "Pre-flight: Elasticsearch Data Check"
DOCS=$(curl -s --max-time 5 \
  "$ES/_cat/indices/auth-logs-*?h=docs.count" 2>/dev/null \
  | grep -v '^0$' | head -1 | tr -d ' ')
if [ -z "$DOCS" ] || [ "$DOCS" = "0" ]; then
  warn "No data in auth-logs-* yet."
  warn "Run 02_configure_logstash.sh first and wait for Logstash to ingest."
  warn "Check: curl http://localhost:9200/_cat/indices/auth-logs-*?v"
  warn "Continuing anyway — dashboard will be empty until data flows."
else
  log "Elasticsearch has data: $DOCS documents in auth-logs-*"
fi

# ── Wait for Kibana ───────────────────────────────────────────────
section "Waiting for Kibana"
info "Waiting up to 3 minutes for Kibana..."
for i in $(seq 1 36); do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$KB/api/status" 2>/dev/null)
  if [ "$CODE" = "200" ]; then log "Kibana ready ✔ (${i}×5s)"; break; fi
  echo -n "."; sleep 5
  [ "$i" -eq 36 ] && error "Kibana not ready after 3 min. Check: sudo journalctl -u kibana -n 30"
done
sleep 3

# ── Helper: post saved object ─────────────────────────────────────
post_object() {
  local type="$1" name="$2" file="$3"
  local code
  code=$(curl -s -o "$TMP/${name}_resp.json" -w "%{http_code}" \
    -X POST "$KB/api/saved_objects/$type" \
    -H "kbn-xsrf: true" -H "Content-Type: application/json" \
    -d @"$file" 2>/dev/null)
  if [ "$code" = "200" ] || [ "$code" = "409" ]; then
    log "  [$type] '$name': HTTP $code"
  else
    warn "  [$type] '$name': HTTP $code — check $TMP/${name}_resp.json"
  fi
}

# ── Helper: get saved object ID by title ─────────────────────────
get_id() {
  local type="$1" title="$2"
  local encoded
  encoded=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$title" 2>/dev/null)
  curl -s "$KB/api/saved_objects/_find?type=$type&search_fields=title&search=$encoded" \
    -H "kbn-xsrf: true" 2>/dev/null \
    | python3 -c "
import sys,json
title='$title'
try:
  d=json.load(sys.stdin)
  for o in d.get('saved_objects',[]):
    if o.get('attributes',{}).get('title')==title:
      print(o['id']); break
except: pass
" 2>/dev/null
}

# ── Step 1: Create Data View ──────────────────────────────────────
section "Data View: auth-logs-*"
cat > "$TMP/dv.json" << 'JSON'
{"data_view":{"title":"auth-logs-*","timeFieldName":"@timestamp","name":"SIEM Auth Logs"}}
JSON
DV_CODE=$(curl -s -o "$TMP/dv_resp.json" -w "%{http_code}" \
  -X POST "$KB/api/data_views/data_view" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d @"$TMP/dv.json" 2>/dev/null)
log "Data View: HTTP $DV_CODE"

# Get Data View ID
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
[ -z "$DV_ID" ] && DV_ID="auth-logs-placeholder"
log "Data View ID: $DV_ID"

# ── Step 2: Visualizations ────────────────────────────────────────
section "Creating Visualizations"

# ── Viz 1: Failed SSH Logins Over Time (area chart) ──────────────
# NOTE: Must be "area" type NOT "histogram" — Kibana 8.x histogram
#       type cannot render a date X axis and shows nothing.
#       date_histogram needs useNormalizedEsInterval:true + min_doc_count:0
python3 - "$DV_ID" "$TMP/viz1.json" << 'PYSC'
import sys, json
dv_id, outfile = sys.argv[1], sys.argv[2]
obj = {
  "attributes": {
    "title": "Failed SSH Logins Over Time",
    "description": "SSH brute force and invalid user attempts plotted over time",
    "visState": json.dumps({
      "title": "Failed SSH Logins Over Time",
      "type": "area",
      "aggs": [
        {
          "id": "1",
          "enabled": True,
          "type": "count",
          "params": {},
          "schema": "metric"
        },
        {
          "id": "2",
          "enabled": True,
          "type": "date_histogram",
          "params": {
            "field": "@timestamp",
            "timeRange": {"from": "now-30d", "to": "now"},
            "useNormalizedEsInterval": True,
            "scaleMetricValues": False,
            "interval": "auto",
            "used_interval": "1h",
            "min_doc_count": 0,
            "drop_partials": False,
            "customInterval": "2h",
            "extended_bounds": {}
          },
          "schema": "segment"
        }
      ],
      "params": {
        "type": "area",
        "grid": {"categoryLines": False},
        "categoryAxes": [
          {
            "id": "CategoryAxis-1",
            "type": "category",
            "position": "bottom",
            "show": True,
            "style": {},
            "scale": {"type": "linear"},
            "labels": {"show": True, "filter": True, "truncate": 100},
            "title": {}
          }
        ],
        "valueAxes": [
          {
            "id": "ValueAxis-1",
            "name": "LeftAxis-1",
            "type": "value",
            "position": "left",
            "show": True,
            "style": {},
            "scale": {"type": "linear", "mode": "normal"},
            "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
            "title": {"text": "Failed Login Attempts"}
          }
        ],
        "seriesParams": [
          {
            "show": True,
            "type": "area",
            "mode": "stacked",
            "data": {"label": "Count", "id": "1"},
            "drawLinesBetweenPoints": True,
            "lineWidth": 2,
            "showCircles": True,
            "circleSize": 3,
            "interpolate": "linear",
            "valueAxis": "ValueAxis-1"
          }
        ],
        "addTooltip": True,
        "addLegend": True,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": False,
        "thresholdLine": {
          "show": False,
          "value": 10,
          "width": 1,
          "style": "full",
          "color": "#E7664C"
        },
        "labels": {}
      }
    }),
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": json.dumps({
        "query": {
          "query": "event_type:ssh_failure OR event_type:invalid_user",
          "language": "kuery"
        },
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
      })
    }
  },
  "references": [
    {
      "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
      "type": "index-pattern",
      "id": dv_id
    }
  ]
}
with open(outfile, 'w') as f:
  json.dump(obj, f, indent=2)
PYSC
post_object "visualization" "Failed SSH Logins Over Time" "$TMP/viz1.json"

# ── Viz 2: Top Attacking IPs (pie — query: src_ip:*) ─────────────
# KEY FIX: query is "src_ip: *" — shows any event where src_ip was parsed
# This handles both ssh_failure AND invalid_user events correctly
python3 - "$DV_ID" "$TMP/viz2.json" << 'PYSC'
import sys, json
dv_id, outfile = sys.argv[1], sys.argv[2]
obj = {
  "attributes": {
    "title": "Top Attacking IPs",
    "description": "Top 10 source IPs — all events where src_ip was parsed (ssh_failure + invalid_user)",
    "visState": json.dumps({
      "title": "Top Attacking IPs",
      "type": "pie",
      "aggs": [
        {"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
        {"id":"2","enabled":True,"type":"terms","params":{
          "field":"src_ip.keyword","orderBy":"1","order":"desc",
          "size":10,"otherBucket":False,"missingBucket":False
        },"schema":"segment"}
      ],
      "params": {
        "type":"pie","addTooltip":True,"addLegend":True,
        "legendPosition":"right","isDonut":False,
        "labels":{"show":True,"values":True,"last_level":True,"truncate":100}
      }
    }),
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": json.dumps({
        "query":{"query":"src_ip: *","language":"kuery"},
        "filter":[],"indexRefName":"kibanaSavedObjectMeta.searchSourceJSON.index"
      })
    }
  },
  "references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":dv_id}]
}
with open(outfile,'w') as f: json.dump(obj,f)
PYSC
post_object "visualization" "Top Attacking IPs" "$TMP/viz2.json"

# ── Viz 3: Security Event Types (donut) ───────────────────────────
python3 - "$DV_ID" "$TMP/viz3.json" << 'PYSC'
import sys, json
dv_id, outfile = sys.argv[1], sys.argv[2]
obj = {
  "attributes": {
    "title": "Security Event Types",
    "description": "All security event categories breakdown",
    "visState": json.dumps({
      "title": "Security Event Types",
      "type": "pie",
      "aggs": [
        {"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
        {"id":"2","enabled":True,"type":"terms","params":{
          "field":"event_type.keyword","orderBy":"1","order":"desc",
          "size":10,"otherBucket":False,"missingBucket":False
        },"schema":"segment"}
      ],
      "params": {
        "type":"pie","addTooltip":True,"addLegend":True,
        "legendPosition":"right","isDonut":True,
        "labels":{"show":True,"values":True,"last_level":True,"truncate":100}
      }
    }),
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": json.dumps({
        "query":{"query":"*","language":"kuery"},
        "filter":[],"indexRefName":"kibanaSavedObjectMeta.searchSourceJSON.index"
      })
    }
  },
  "references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":dv_id}]
}
with open(outfile,'w') as f: json.dump(obj,f)
PYSC
post_object "visualization" "Security Event Types" "$TMP/viz3.json"

# ── Viz 4: Failed Logins Today (metric) ───────────────────────────
python3 - "$DV_ID" "$TMP/viz4.json" << 'PYSC'
import sys, json
dv_id, outfile = sys.argv[1], sys.argv[2]
obj = {
  "attributes": {
    "title": "Failed Logins Today",
    "description": "Total failed SSH login attempts",
    "visState": json.dumps({
      "title": "Failed Logins Today",
      "type": "metric",
      "aggs": [{"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"}],
      "params": {
        "addTooltip":True,"addLegend":False,"type":"metric",
        "metric":{
          "percentageMode":False,"useRanges":True,
          "colorSchema":"Green to Red","metricColorMode":"Background",
          "colorsRange":[
            {"from":0,"to":10},
            {"from":10,"to":50},
            {"from":50,"to":99999}
          ],
          "labels":{"show":True},"invertColors":False,
          "style":{"bgFill":"#000","bgColor":True,"labelColor":False,
            "subText":"SSH Failures","fontSize":60}
        }
      }
    }),
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": json.dumps({
        "query":{"query":"event_type:ssh_failure OR event_type:invalid_user","language":"kuery"},
        "filter":[],"indexRefName":"kibanaSavedObjectMeta.searchSourceJSON.index"
      })
    }
  },
  "references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":dv_id}]
}
with open(outfile,'w') as f: json.dump(obj,f)
PYSC
post_object "visualization" "Failed Logins Today" "$TMP/viz4.json"

# ── Viz 5: SSH Brute Force Report (data table — top IPs) ──────────
python3 - "$DV_ID" "$TMP/viz5.json" << 'PYSC'
import sys, json
dv_id, outfile = sys.argv[1], sys.argv[2]
obj = {
  "attributes": {
    "title": "SSH Brute Force Report — Top IPs & Users",
    "description": "Table: Top attacking IPs and targeted usernames",
    "visState": json.dumps({
      "title": "SSH Brute Force Report — Top IPs & Users",
      "type": "table",
      "aggs": [
        {"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
        {"id":"2","enabled":True,"type":"terms","params":{
          "field":"src_ip.keyword","orderBy":"1","order":"desc","size":15,
          "otherBucket":False,"missingBucket":False
        },"schema":"bucket"},
        {"id":"3","enabled":True,"type":"terms","params":{
          "field":"username.keyword","orderBy":"1","order":"desc","size":5,
          "otherBucket":False,"missingBucket":False
        },"schema":"bucket"}
      ],
      "params": {
        "perPage":10,"showPartialRows":False,"showMetricsAtAllLevels":False,
        "sort":{"columnIndex":None,"direction":None},
        "showTotal":True,"totalFunc":"sum",
        "dimensions":{
          "metrics":[{"accessor":2,"format":{"id":"number"},"params":{},"aggType":"count"}],
          "buckets":[
            {"accessor":0,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"},
            {"accessor":1,"format":{"id":"terms","params":{"id":"string","otherBucketLabel":"Other","missingBucketLabel":"Missing"}},"params":{},"aggType":"terms"}
          ]
        }
      }
    }),
    "uiStateJSON": json.dumps({"vis":{"params":{"sort":{"columnIndex":2,"direction":"desc"}}}}),
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": json.dumps({
        "query":{"query":"src_ip: *","language":"kuery"},
        "filter":[],"indexRefName":"kibanaSavedObjectMeta.searchSourceJSON.index"
      })
    }
  },
  "references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":dv_id}]
}
with open(outfile,'w') as f: json.dump(obj,f)
PYSC
post_object "visualization" "SSH Brute Force Report — Top IPs & Users" "$TMP/viz5.json"

# ── Viz 6: Log Health Report (data table — event severity) ────────
python3 - "$DV_ID" "$TMP/viz6.json" << 'PYSC'
import sys, json
dv_id, outfile = sys.argv[1], sys.argv[2]
obj = {
  "attributes": {
    "title": "Log Health Report — Event Severity Breakdown",
    "description": "Table: All events grouped by severity and category",
    "visState": json.dumps({
      "title": "Log Health Report — Event Severity Breakdown",
      "type": "table",
      "aggs": [
        {"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
        {"id":"2","enabled":True,"type":"terms","params":{
          "field":"event_severity.keyword","orderBy":"1","order":"desc","size":10,
          "otherBucket":False,"missingBucket":False
        },"schema":"bucket"},
        {"id":"3","enabled":True,"type":"terms","params":{
          "field":"event_type.keyword","orderBy":"1","order":"desc","size":10,
          "otherBucket":False,"missingBucket":False
        },"schema":"bucket"},
        {"id":"4","enabled":True,"type":"terms","params":{
          "field":"username.keyword","orderBy":"1","order":"desc","size":5,
          "otherBucket":False,"missingBucket":False
        },"schema":"bucket"}
      ],
      "params": {
        "perPage":15,"showPartialRows":False,"showMetricsAtAllLevels":False,
        "sort":{"columnIndex":None,"direction":None},
        "showTotal":True,"totalFunc":"sum"
      }
    }),
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": json.dumps({
        "query":{"query":"event_type: *","language":"kuery"},
        "filter":[],"indexRefName":"kibanaSavedObjectMeta.searchSourceJSON.index"
      })
    }
  },
  "references":[{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":dv_id}]
}
with open(outfile,'w') as f: json.dump(obj,f)
PYSC
post_object "visualization" "Log Health Report — Event Severity Breakdown" "$TMP/viz6.json"

# ── Step 3: Get all visualization IDs ────────────────────────────
section "Fetching Visualization IDs"
sleep 2  # brief pause so Kibana registers objects

ID1=$(get_id "visualization" "Failed SSH Logins Over Time")
ID2=$(get_id "visualization" "Top Attacking IPs")
ID3=$(get_id "visualization" "Security Event Types")
ID4=$(get_id "visualization" "Failed Logins Today")
ID5=$(get_id "visualization" "SSH Brute Force Report — Top IPs & Users")
ID6=$(get_id "visualization" "Log Health Report — Event Severity Breakdown")

log "IDs:"
log "  1 (bar)    : ${ID1:-MISSING}"
log "  2 (pie/IPs): ${ID2:-MISSING}"
log "  3 (donut)  : ${ID3:-MISSING}"
log "  4 (metric) : ${ID4:-MISSING}"
log "  5 (table1) : ${ID5:-MISSING}"
log "  6 (table2) : ${ID6:-MISSING}"

# ── Step 4: Build Dashboard ───────────────────────────────────────
section "Building Dashboard"

python3 - "$ID1" "$ID2" "$ID3" "$ID4" "$ID5" "$ID6" "$DV_ID" "$TMP/dash.json" << 'PYSC'
import sys, json
id1,id2,id3,id4,id5,id6,dv_id,outfile = sys.argv[1:]

# Dashboard layout (x, y, w, h) on a 48-unit grid
# Row 1: histogram (wide) | metric (narrow)
# Row 2: pie IPs | donut event types
# Row 3: SSH brute force table (full width)
# Row 4: log health table (full width)
layout = [
  (id1, "Failed SSH Logins Over Time",               0,  0, 36, 15),
  (id4, "Failed Logins Today",                       36, 0, 12, 15),
  (id2, "Top Attacking IPs",                         0, 15, 24, 15),
  (id3, "Security Event Types",                      24,15, 24, 15),
  (id5, "SSH Brute Force Report — Top IPs & Users",  0, 30, 48, 18),
  (id6, "Log Health Report — Event Severity Breakdown", 0, 48, 48, 18),
]

panels = []
refs   = []
for idx, (viz_id, title, x, y, w, h) in enumerate(layout, 1):
  if not viz_id or viz_id == "auth-logs-placeholder":
    print(f"  SKIP (no ID): {title}")
    continue
  key = f"panel_{idx}"
  panels.append({
    "version": "8.0.0",
    "gridData": {"x": x, "y": y, "w": w, "h": h, "i": key},
    "panelIndex": key,
    "embeddableConfig": {"enhancements": {}},
    "panelRefName": key
  })
  refs.append({"name": key, "type": "visualization", "id": viz_id})
  print(f"  Panel {idx}: {title}")

obj = {
  "attributes": {
    "title": "Linux Security Monitoring Dashboard",
    "description": "SIEM Dashboard — SSH brute force, event types, attacking IPs, log health. Author: RH Vitharana | SLIIT",
    "panelsJSON": json.dumps(panels),
    "optionsJSON": json.dumps({
      "useMargins": True,
      "syncColors": False,
      "hidePanelTitles": False
    }),
    # Auto-refresh every 45 seconds + default time range last 24 hours
    "timeRestore": True,
    "timeFrom": "now-24h",
    "timeTo": "now",
    "refreshInterval": {
      "pause": False,
      "value": 45000
    },
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": json.dumps({
        "query": {"query": "", "language": "kuery"},
        "filter": []
      })
    }
  },
  "references": refs
}
with open(outfile, 'w') as f:
  json.dump(obj, f)
print(f"Dashboard JSON written with {len(panels)} panels")
PYSC

DASH_CODE=$(curl -s -o "$TMP/dash_resp.json" -w "%{http_code}" \
  -X POST "$KB/api/saved_objects/dashboard" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d @"$TMP/dash.json" 2>/dev/null)

if [ "$DASH_CODE" = "200" ]; then
  DASH_ID=$(python3 -c "
import json
d=json.load(open('$TMP/dash_resp.json'))
print(d.get('id',''))
" 2>/dev/null)
  log "Dashboard created ✔  ID: $DASH_ID"
else
  warn "Dashboard HTTP $DASH_CODE — check $TMP/dash_resp.json"
  cat "$TMP/dash_resp.json" | python3 -m json.tool 2>/dev/null | tail -10 | tee -a "$SETUP_LOG"
fi

rm -rf "$TMP"

HOST_IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║   SIEM Dashboard Ready ✔                        ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  🌐  Dashboard : ${CYAN}http://${HOST_IP}:5601/app/dashboards${RESET}"
echo ""
echo -e "  ${BOLD}Dashboard panels:${RESET}"
echo "    1. Failed SSH Logins Over Time   (area chart)"
echo "    2. Failed Logins Today           (metric counter)"
echo "    3. Top Attacking IPs             (pie chart — src_ip:*)"
echo "    4. Security Event Types          (donut chart)"
echo "    5. SSH Brute Force Report        (table: IPs × usernames)"
echo "    6. Log Health Report             (table: severity × event type)"
echo ""
echo -e "  ${BOLD}Auto-refresh:${RESET} ⏱  Every 45 seconds (active on open)"
echo -e "  ${BOLD}Default time range:${RESET} Last 24 hours"
echo ""
echo -e "  ${BOLD}Cron automation:${RESET}"
echo "    • SSH brute force scan — hourly"
echo "    • Log health report    — daily 08:00"
echo "    • Service status check — every 30 min"
echo ""
echo -e "  ${BOLD}Manual run:${RESET}"
echo -e "    ${CYAN}sudo bash /opt/siem-project/scripts/ssh_bruteforce.sh${RESET}"
echo -e "    ${CYAN}sudo bash /opt/siem-project/scripts/log_monitor.sh${RESET}"
echo -e "    ${CYAN}sudo bash /opt/siem-project/scripts/siem_status.sh${RESET}"
