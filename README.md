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
- **Honeypot** (optional): decoy port listeners to catch attackers probing your server, with stats and data visualization
- **Geo-IP enrichment**: automatic country/city/ISP lookup for attacker IPs via ip-api.com (free, no API key)
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
| `HONEYPOT_ENABLED` | No | `true` to enable honeypot decoy ports (default: `false`) |
| `HONEYPOT_PORTS` | No | Comma-separated decoy ports (default: `2222,8080,3389,5900`) |
| `HONEYPOT_DATA_PATH` | No | Path for honeypot data file (default: `/var/log/idps-agent/honeypot.json`) |
| `HONEYPOT_HTTP_ENABLED` | No | `true` to enable HTTP honeypot with fake login pages (default: `false`) |
| `HONEYPOT_HTTP_PORT` | No | HTTP honeypot listen port (default: `8080`) |
| `GEOIP_ENABLED` | No | `false` to disable geo-IP lookups (default: `true`) |

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
| `/honeypot` | Honeypot stats summary |
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
| honeypot | Connection to a decoy honeypot port | HIGH |
| honeypot (HTTP) | Credential attempt on fake admin login page | HIGH |

## AI Integration

When a HIGH or CRITICAL threat is detected, Claude AI:

1. Analyzes the full context (log data, IP history, detection rule, protocol, HTTP method/status, user-agent, origin)
2. Classifies the attack type with a confidence score
3. Recommends an action: `block`, `monitor`, `ignore`, or `escalate`
4. Provides a human-readable explanation

**Autonomous Mode** (`AUTONOMOUS_MODE=true`): AI-recommended blocks with >= 70% confidence are executed automatically.

**Human-in-the-loop** (`AUTONOMOUS_MODE=false`): AI suggests actions, operator confirms via Telegram commands.

AI decisions are logged to `/var/log/idps-agent/ai-decisions.log`.

## Honeypot

An optional integrated honeypot that listens on configurable decoy ports to detect attackers actively probing your server.

### How it works

1. TCP servers listen on decoy ports (default: 2222, 8080, 3389, 5900)
2. Any connection is logged with the attacker's IP, timestamp, and captured payload data
3. Each connection generates a HIGH-severity `honeypot` threat that flows through the standard detection pipeline (alerts, AI analysis, autonomous blocking)
4. Stats are persisted to disk with a 7-day rolling window

### Enabling

```bash
# In your systemd service environment
HONEYPOT_ENABLED=true
HONEYPOT_PORTS=2222,8080,3389,5900  # optional, these are the defaults
```

### Data Visualization

- **HTML report**: `GET /honeypot/report` — full visual report with bar charts for top attacker IPs, most probed ports, hourly connection distribution, and recent payloads
- **JSON stats**: `GET /honeypot/stats` — raw stats data for programmatic access
- **Telegram**: `/honeypot` command — inline summary with top attackers and ports

Both HTTP endpoints require the same `Authorization: Bearer` token as `/stats`.

```bash
# View HTML report in browser
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:3001/honeypot/report > report.html

# Get JSON stats
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:3001/honeypot/stats
```

### Port Selection Tips

Choose ports that attackers commonly scan but your server doesn't use:
- `2222` — alternate SSH
- `8080` — HTTP proxy / alternate web
- `3389` — RDP (Windows Remote Desktop)
- `5900` — VNC
- `6379` — Redis
- `27017` — MongoDB
- `3306` — MySQL

Avoid ports used by your actual services. Ports below 1024 require `CAP_NET_BIND_SERVICE` or root.

### HTTP Honeypot

An optional HTTP server that serves convincing fake admin login pages to capture credential stuffing attempts and fingerprint scanning tools.

#### How it works

1. An HTTP server listens on a configurable port (default: 8080)
2. Serves realistic fake login pages for common admin paths:
   - `/wp-admin`, `/wp-login.php` — WordPress login
   - `/admin`, `/login`, `/dashboard` — generic admin panel
   - `/phpmyadmin` — phpMyAdmin login
   - All other paths return a 404 that mimics a real nginx server
3. POST requests to login pages capture submitted credentials (username/password)
4. Returns "Invalid credentials" responses to keep bots engaged and trying more passwords
5. Every request is logged with IP, path, User-Agent, and timestamp
6. User-Agent strings are checked against known scanner tool signatures (sqlmap, Nikto, Hydra, Nmap, etc.)
7. Credential attempts generate HIGH-severity threats that flow through the standard alerting pipeline

#### Enabling

```bash
# In your systemd service environment
HONEYPOT_HTTP_ENABLED=true
HONEYPOT_HTTP_PORT=8080  # optional, 8080 is the default
```

**Note:** If you use the TCP honeypot on port 8080 (`HONEYPOT_PORTS`), remove 8080 from that list when enabling the HTTP honeypot to avoid port conflicts.

## Geo-IP Enrichment

Attacker IPs are automatically enriched with geographic data (country, city, ISP, hosting/proxy flags) using the free [ip-api.com](http://ip-api.com) service. No API key is required.

- **Enabled by default** — set `GEOIP_ENABLED=false` to disable
- Results are cached in memory (up to 1,000 IPs) to avoid duplicate lookups
- Rate-limited to 45 requests/minute (ip-api.com free tier limit)
- Private/reserved IPs (10.x, 192.168.x, 127.x, etc.) are skipped automatically
- Geo data appears in honeypot reports: top attacker IPs show country codes, and a "Top Countries" breakdown is included in all report formats (Telegram, HTML, ASCII)

## Architecture

```
src/
├── index.js              # Main entry — wires everything together
├── store.js              # In-memory IP tracking with TTL cleanup
├── parsers/              # Log line parsers (nginx, auth, ufw, fail2ban, journal)
├── detectors/            # Detection rules (one per file)
├── alerters/             # Telegram alerts + daily summary
├── ai/                   # Claude AI analyzer, autonomous actions, threat memory
├── honeypot/             # Optional decoy port listeners, stats, and reports
├── api/                  # HTTP health/stats endpoints
├── bot/                  # Telegram bot command handler
└── utils/                # Logger, sanitizer, file tailer, cooldown manager, origin identifier, geo-IP
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