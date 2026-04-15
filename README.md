<p align="center">
  <img src="assets/logo.png" alt="IDPS Agent" width="500">
</p>

# IDPS Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE)

Intrusion Detection & Prevention System for Node.js applications on GCP, with AI-powered threat analysis.

## Overview

IDPS Agent monitors your server's log files in real-time, detects threats using configurable rules, sends alerts via Telegram, and optionally uses Claude AI to analyze threats and take autonomous defensive actions.

**Designed for:** GCP e2-micro instances running Node.js behind Nginx + Cloudflare.

## Features

- **10 detection rules**: brute-force, port scanning, HTTP flood, 4xx/5xx spikes, SSH abuse, scanner user-agents, geo-anomaly, SQL injection, XSS, post-ban re-access
- **Real-time log monitoring**: Nginx, auth.log, UFW, fail2ban, systemd journal
- **Telegram alerts**: severity-tagged, with protocol/request/origin context and inline action commands
- **AI analysis**: Claude evaluates HIGH/CRITICAL threats, classifies attacks, recommends actions
- **Autonomous mode**: AI-driven IP blocking via fail2ban and iptables (configurable)
- **Human-in-the-loop**: Telegram commands for manual blocking, whitelisting, reports
- **Daily summaries** at 08:00 AM, **weekly AI reports** on Mondays
- **HTTP API**: `/health` and `/stats` endpoints
- **Lightweight**: single process, in-memory store, minimal dependencies

## Requirements

- Node.js >= 20
- Ubuntu 24 (GCP e2-micro)
- Nginx (configured as reverse proxy)
- Cloudflare (in front of the server)
- fail2ban (installed and running)
- iptables (available)

## Quick Setup

```bash
# Clone the repo (don't clone into /opt/idps-agent — setup.sh installs there)
git clone <your-repo-url> ~/idps-agent
cd ~/idps-agent

# Run setup (as root)
sudo bash setup.sh
```

The setup script will:
1. Create a `idps-agent` system user
2. Set up log and data directories
3. Install Node.js dependencies
4. Configure file permissions and sudoers
5. Install the systemd service

## Configuration

All configuration is via **environment variables** set in the systemd service file:

```bash
sudo nano /etc/systemd/system/idps-agent.service
```

| Variable | Required | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | Yes | Telegram Bot API token |
| `TELEGRAM_CHAT_ID` | Yes | Telegram chat ID for alerts |
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key for Claude AI |
| `ANTHROPIC_MODEL` | No | Claude model for AI analysis (default: `claude-sonnet-4-20250514`) |
| `ANTHROPIC_DECISION_MODEL` | No | Claude model for autonomous-mode threat decisions (default: `claude-haiku-4-5-20251001`) |
| `AUTONOMOUS_MODE` | No | `true` to enable auto-blocking (default: `false`) |
| `MONITORED_SERVICE` | Yes | systemd service name of your app |
| `API_BEARER_TOKEN` | Yes | Bearer token for `/stats` endpoint |
| `ALLOWED_COUNTRIES` | No | Comma-separated country codes (default: `BR,US`) |
| `IDPS_PORT` | No | HTTP API port (default: `3001`) |

## Nginx Log Format

IDPS Agent expects the real client IP (from Cloudflare) as the first field in Nginx access logs. Add this to your `nginx.conf`:

```nginx
http {
    log_format cf '$http_cf_connecting_ip - $remote_user [$time_local] '
                  '"$request" $status $body_bytes_sent '
                  '"$http_referer" "$http_user_agent"';

    access_log /var/log/nginx/access.log cf;
}
```

### IP Blocking via Nginx

IDPS Agent automatically manages `/etc/nginx/blocked-ips.conf` to block banned IPs at the HTTP level (essential when behind Cloudflare, since iptables only sees Cloudflare's IPs for web traffic). Add this include to each nginx `server` block:

```nginx
server {
    include /etc/nginx/blocked-ips.conf;
    # ... rest of your config
}
```

## Running

```bash
# Start
sudo systemctl start idps-agent

# Enable on boot
sudo systemctl enable idps-agent

# Check status
sudo systemctl status idps-agent

# View logs
sudo journalctl -u idps-agent -f

# Health check
curl http://localhost:3001/health

# Stats (protected)
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:3001/stats
```

## Telegram Commands

| Command | Description |
|---|---|
| `/block_ip <IP>` | Block an IP via fail2ban + iptables |
| `/whitelist <IP>` | Suppress future alerts for an IP |
| `/report <IP>` | AI deep-dive report on IP activity |
| `/status` | Current threat summary and stats |
| `/help` | Show available commands |

## Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| brute-force | 5+ failed logins (401/403) from same IP in 60s | MEDIUM/HIGH |
| port-scan | 10+ unique endpoints from same IP in 30s | HIGH |
| http-flood | 100+ requests from same IP in 60s | HIGH/CRITICAL |
| 4xx-spike | 30+ client errors globally in 1 minute | MEDIUM |
| 5xx-spike | 3+ server errors globally in 1 minute | HIGH |
| ssh-abuse | 3+ failed SSH attempts from same IP | HIGH/CRITICAL |
| suspicious-user-agent | Known scanner signatures (sqlmap, nikto, nmap, etc.) | HIGH |
| geo-anomaly | Request from non-allowlisted country | LOW |
| sqli-attempt | SQL injection patterns in URL | CRITICAL |
| xss-attempt | XSS patterns in URL | HIGH |
| post-ban-access | Recently-unbanned IP accessing server again | MEDIUM |

## AI Integration

When a HIGH or CRITICAL threat is detected, Claude AI:

1. Analyzes the full context (log data, IP history, detection rule, protocol, HTTP method/status, user-agent, origin)
2. Classifies the attack type with a confidence score
3. Recommends an action: `block`, `monitor`, `ignore`, or `escalate`
4. Provides a human-readable explanation

**Autonomous Mode** (`AUTONOMOUS_MODE=true`): AI-recommended blocks with >= 70% confidence are executed automatically.

**Human-in-the-loop** (`AUTONOMOUS_MODE=false`): AI suggests actions, operator confirms via Telegram commands.

AI decisions are logged to `/var/log/idps-agent/ai-decisions.log`.

## Architecture

```
src/
├── index.js              # Main entry — wires everything together
├── store.js              # In-memory IP tracking with TTL cleanup
├── parsers/              # Log line parsers (nginx, auth, ufw, fail2ban, journal)
├── detectors/            # Detection rules (one per file)
├── alerters/             # Telegram alerts + daily summary
├── ai/                   # Claude AI analyzer, autonomous actions, threat memory
├── api/                  # HTTP health/stats endpoints
├── bot/                  # Telegram bot command handler
└── utils/                # Logger, sanitizer, file tailer, cooldown manager, origin identifier
```

## Deployment Recommendations

1. Start with `AUTONOMOUS_MODE=false` for the first few days
2. Review AI decisions in `/var/log/idps-agent/ai-decisions.log`
3. Use `/report <IP>` on suspicious IPs to validate AI accuracy
4. Enable autonomous mode once confident in the AI's judgement
5. Monitor memory usage via `/stats` — the in-memory store is cleaned every 5 minutes

## Files

| File | Purpose |
|---|---|
| `config.js` | Central config (reads environment variables) |
| `idps-agent.service` | systemd service template |
| `setup.sh` | Automated setup for Ubuntu 24 |
| `.gitignore` | Excludes secrets and logs |