#!/bin/bash
# ================================================================
#  run.sh — SIEM Project Master Installer
#  Runs all setup steps in order:
#    01_install_elk.sh
#    02_configure_logstash.sh
#    03_install_scripts.sh
#    04_setup_kibana.sh
#
#  Each script runs independently — if one fails the installer
#  stops and tells you exactly which step failed and why.
#
#  Author : RV Vitharana | SLIIT — BSc (Hons) IT (Cyber Security)
# ================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Root check ────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[✘] Run as root: sudo bash run.sh${RESET}"
  exit 1
fi

# ── Locate script directory ───────────────────────────────────────
# All scripts must be in the same folder as run.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

STEPS=(
  "01_install_elk.sh"
  "02_configure_logstash.sh"
  "03_install_scripts.sh"
  "04_setup_kibana.sh"
)

STEP_LABELS=(
  "Install Java + ELK Stack"
  "Configure Logstash Pipeline"
  "Install SIEM Scripts + Cron Jobs"
  "Setup Kibana Dashboard"
)

# ── Banner ────────────────────────────────────────────────────────
clear
echo -e "${CYAN}${BOLD}"
echo "  ███████╗██╗███████╗███╗   ███╗"
echo "  ██╔════╝██║██╔════╝████╗ ████║"
echo "  ███████╗██║█████╗  ██╔████╔██║"
echo "  ╚════██║██║██╔══╝  ██║╚██╔╝██║"
echo "  ███████║██║███████╗██║ ╚═╝ ██║"
echo "  ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝"
echo -e "${RESET}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║   Security Information & Event Management               ║"
echo "  ║   Linux Log Analysis & SIEM Visualization               ║"
echo "  ╠══════════════════════════════════════════════════════════╣"
echo "  ║   Author  : RV Vitharana                                ║"
echo "  ║   Degree  : BSc (Hons) IT — Cyber Security              ║"
echo "  ║   Uni     : SLIIT                                       ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  ${BOLD}Install location :${RESET} $SCRIPT_DIR"
echo -e "  ${BOLD}Started at       :${RESET} $(date)"
echo -e "  ${BOLD}System           :${RESET} $(hostname)  |  $(uname -r)"
echo ""

# ── Check all scripts exist before starting ───────────────────────
echo -e "${BOLD}${BLUE}━━━ Pre-flight: Checking All Scripts ━━━${RESET}"
ALL_FOUND=true
for i in "${!STEPS[@]}"; do
  script="${SCRIPT_DIR}/${STEPS[$i]}"
  if [ -f "$script" ]; then
    echo -e "  ${GREEN}[✔]${RESET} Found: ${STEPS[$i]}"
  else
    echo -e "  ${RED}[✘]${RESET} MISSING: ${STEPS[$i]}"
    ALL_FOUND=false
  fi
done

if ! $ALL_FOUND; then
  echo ""
  echo -e "${RED}[✘] One or more scripts are missing from: $SCRIPT_DIR${RESET}"
  echo -e "    Make sure all scripts are in the same folder as run.sh"
  echo -e "    Expected files:"
  for s in "${STEPS[@]}"; do
    echo -e "      $SCRIPT_DIR/$s"
  done
  exit 1
fi

echo ""
echo -e "  ${GREEN}All scripts found ✔${RESET}"
echo ""

# ── Confirm ───────────────────────────────────────────────────────
echo -e "${YELLOW}  This will install the full SIEM stack (ELK + scripts + dashboard).${RESET}"
echo -e "  ${YELLOW}Requires internet connection and ~4GB RAM.${RESET}"
echo ""
read -rp "  Press ENTER to start, or Ctrl+C to cancel... "
echo ""

# ── Run each step ─────────────────────────────────────────────────
FAILED_STEP=""
START_TIME=$(date +%s)

for i in "${!STEPS[@]}"; do
  STEP_NUM=$((i + 1))
  SCRIPT_FILE="${SCRIPT_DIR}/${STEPS[$i]}"
  LABEL="${STEP_LABELS[$i]}"

  echo -e "\n${BOLD}${BLUE}━━━ STEP ${STEP_NUM}/${#STEPS[@]} — ${LABEL} ━━━${RESET}"
  echo -e "  ${CYAN}▶ Running: $(basename "$SCRIPT_FILE")${RESET}\n"

  STEP_START=$(date +%s)

  # Run the script — output goes directly to terminal
  bash "$SCRIPT_FILE"
  EXIT_CODE=$?

  STEP_END=$(date +%s)
  STEP_TIME=$(( STEP_END - STEP_START ))

  echo ""
  if [ $EXIT_CODE -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}[✔] Step $STEP_NUM complete — ${LABEL} (${STEP_TIME}s)${RESET}"
  else
    echo -e "  ${RED}${BOLD}[✘] Step $STEP_NUM FAILED — ${LABEL} (exit code: $EXIT_CODE)${RESET}"
    echo ""
    echo -e "  ${YELLOW}Troubleshooting:${RESET}"
    echo -e "    • Check the error output above"
    echo -e "    • Re-run just this step: ${CYAN}sudo bash $SCRIPT_FILE${RESET}"
    echo -e "    • Check logs: ${CYAN}sudo journalctl -u logstash -n 30${RESET}"
    echo -e "    •             ${CYAN}sudo journalctl -u elasticsearch -n 30${RESET}"
    FAILED_STEP="$LABEL"
    break
  fi

  # Brief pause between steps so services settle
  if [ $STEP_NUM -lt ${#STEPS[@]} ]; then
    echo -e "  ${CYAN}[i] Pausing 5s before next step...${RESET}"
    sleep 5
  fi

  echo ""
done

# ── Final summary ─────────────────────────────────────────────────
END_TIME=$(date +%s)
TOTAL_TIME=$(( END_TIME - START_TIME ))
MINUTES=$(( TOTAL_TIME / 60 ))
SECONDS=$(( TOTAL_TIME % 60 ))
HOST_IP=$(hostname -I | awk '{print $1}')

echo ""
if [ -z "$FAILED_STEP" ]; then
  echo -e "${GREEN}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════════════╗"
  echo "  ║   ✔  SIEM Project Fully Installed                       ║"
  echo "  ╚══════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
  echo -e "  ${BOLD}Total install time :${RESET} ${MINUTES}m ${SECONDS}s"
  echo -e "  ${BOLD}Completed at       :${RESET} $(date)"
  echo ""
  echo -e "  ${BOLD}Access your SIEM:${RESET}"
  echo -e "    🌐  Kibana Dashboard  : ${CYAN}http://${HOST_IP}:5601/app/dashboards${RESET}"
  echo -e "    🔌  Elasticsearch API : ${CYAN}http://${HOST_IP}:9200${RESET}"
  echo ""
  echo -e "  ${BOLD}Installed scripts:${RESET}"
  echo -e "    ${CYAN}sudo bash /opt/siem-project/scripts/ssh_bruteforce.sh${RESET}"
  echo -e "    ${CYAN}sudo bash /opt/siem-project/scripts/log_monitor.sh${RESET}"
  echo -e "    ${CYAN}sudo bash /opt/siem-project/scripts/siem_status.sh${RESET}"
  echo ""
  echo -e "  ${BOLD}Cron automation active:${RESET}"
  echo "    • SSH brute force scan — every hour"
  echo "    • Log health report    — daily at 08:00"
  echo "    • Service status check — every 30 min"
  echo ""
  echo -e "  ${YELLOW}Tip:${RESET} Set Kibana time range to 'Last 7 days' to see your data."
else
  echo -e "${RED}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════════════╗"
  echo "  ║   ✘  Installation stopped at a failed step              ║"
  echo "  ╚══════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
  echo -e "  ${BOLD}Failed step :${RESET} ${RED}$FAILED_STEP${RESET}"
  echo -e "  ${BOLD}Time elapsed:${RESET} ${MINUTES}m ${SECONDS}s"
  echo ""
  echo -e "  ${BOLD}To retry from the failed step only:${RESET}"
  for i in "${!STEP_LABELS[@]}"; do
    if [ "${STEP_LABELS[$i]}" = "$FAILED_STEP" ]; then
      echo -e "    ${CYAN}sudo bash ${SCRIPT_DIR}/${STEPS[$i]}${RESET}"
    fi
  done
  echo ""
  echo -e "  Once fixed, continue with the remaining steps in order."
fi
