# Linux Log Analysis, Automation & SIEM Visualization

> A complete end-to-end security monitoring pipeline built on Linux — from raw log collection to automated threat detection and live SIEM dashboards using the ELK Stack.

**Author:** RV Vitharana  
**Degree:** BSc (Hons) Information Technology — Cyber Security  
**University:** Sri Lanka Institute of Information Technology (SLIIT)

---

## Project Overview

This project replicates a real-world SOC (Security Operations Centre) workflow on a Linux system. It collects system logs, parses them for security events, runs automated threat detection scripts, and visualises everything in a Kibana SIEM dashboard.

### What it does

- Collects and parses Linux auth logs (`/var/log/auth.log`, `/var/log/syslog`)
- Detects SSH brute-force attacks, invalid user attempts, and privilege escalations
- Runs automated Bash scripts via cron to generate hourly security reports
- Ingests logs into Elasticsearch via Logstash for full-text search and indexing
- Displays real-time security dashboards in Kibana with charts, maps, and metrics

---

## Tech Stack

| Component | Purpose |
|---|---|
| Ubuntu / Debian / Kali Linux | Host operating system |
| Bash scripting | Log analysis and automation |
| grep / awk / sed | Log parsing and pattern extraction |
| Logstash | Log ingestion and field parsing |
| Elasticsearch | Log indexing and search engine |
| Kibana | SIEM dashboard and visualisation |
| Cron | Scheduled automation |

---

## Quick Install (Ubuntu / Debian / Kali)

Clone the repository and run the installer with one command:

```bash
git clone https://github.com/avrviranga/linux-siem-lab.git
cd linux-siem-lab
sudo bash run.sh
```

The installer will automatically:

1. Detect your Linux distribution
2. Check system requirements (RAM, disk, internet)
3. Install Java, Elasticsearch, Kibana, and Logstash
4. Configure the Logstash pipeline for auth log ingestion
5. Copy and make executable all analysis scripts
6. Set up cron jobs for automated hourly/daily scans
7. Configure firewall rules for Kibana and Elasticsearch
8. Verify all services are running
9. Print a summary with your access URLs

---

## System Requirements

| Requirement | Minimum |
|---|---|
| OS | Ubuntu 20.04+, Debian 11+, Kali Linux 2022+ |
| RAM | 4 GB (8 GB recommended) |
| Disk | 20 GB free |
| Internet | Required for installation |
| Privileges | Must run as root (`sudo`) |

---

## Manual Usage

If you already have ELK Stack installed, you can use the scripts individually:

```bash
# Detect SSH brute force attempts (threshold: 5 attempts)
sudo bash scripts/ssh_bruteforce.sh

# Use a custom threshold (e.g., 3 attempts triggers an alert)
sudo bash scripts/ssh_bruteforce.sh 3

# Monitor all log files for security keywords
sudo bash scripts/log_monitor.sh

# Check if all SIEM services are running
sudo bash scripts/siem_status.sh
```

---

## Accessing the Dashboard

After installation, open your browser and navigate to:

```
http://YOUR_SERVER_IP:5601
```

## Log Data Flow

```
/var/log/auth.log
        │
        ▼
   Logstash (parse + tag events)
        │
        ▼
Elasticsearch (index + store)
        │
        ▼
  Kibana (visualize + dashboard)
```

---

## Security Events Detected

| Event | Tag | Severity |
|---|---|---|
| Failed SSH password | `ssh_failure` | High |
| Invalid SSH username | `invalid_user` | High |
| Successful SSH login | `ssh_success` | Low |
| Sudo usage | `sudo_usage` | Medium |
| Session opened/closed | `session_open/close` | Info |
| User account changes | `user_management` | High |

---

## Learning Outcomes

By building and running this project, I developed practical skills in:

- Linux system administration and log file management
- Text processing with `grep`, `awk`, and `sed`
- Bash scripting and cron-based automation
- ELK Stack deployment and configuration
- Logstash Grok pattern parsing
- Kibana dashboard design and data visualisation
- SOC analyst workflows and threat detection concepts

---

## License

MIT License — free to use, modify, and distribute with attribution.
