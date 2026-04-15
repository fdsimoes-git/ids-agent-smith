#!/usr/bin/env bash
# Simulate various attack patterns by writing to local log files.
# Usage: bash test/simulate.sh [scenario]
# Scenarios: brute-force, port-scan, http-flood, ssh, sqli, xss, scanner, geo, 5xx, banned, all

set -euo pipefail

LOG_DIR="$(dirname "$0")/logs"
NGINX_LOG="$LOG_DIR/access.log"
AUTH_LOG="$LOG_DIR/auth.log"
UFW_LOG="$LOG_DIR/ufw.log"
F2B_LOG="$LOG_DIR/fail2ban.log"

NOW=$(date +"%d/%b/%Y:%H:%M:%S +0000")
SYSLOG_NOW=$(date +"%b %e %H:%M:%S")
F2B_NOW=$(date +"%Y-%m-%d %H:%M:%S")

scenario="${1:-all}"

brute_force() {
  echo ">>> Simulating brute-force attack (6 failed logins from 192.168.1.100)"
  for i in $(seq 1 6); do
    echo "192.168.1.100 - - [$NOW] \"POST /api/login HTTP/1.1\" 401 45 \"-\" \"Mozilla/5.0\"" >> "$NGINX_LOG"
    sleep 0.1
  done
}

port_scan() {
  echo ">>> Simulating port scan (12 unique endpoints from 10.0.0.55)"
  for i in $(seq 1 12); do
    echo "10.0.0.55 - - [$NOW] \"GET /path-$i HTTP/1.1\" 404 0 \"-\" \"Mozilla/5.0\"" >> "$NGINX_LOG"
    sleep 0.1
  done
}

http_flood() {
  echo ">>> Simulating HTTP flood (105 requests from 172.16.0.200)"
  for i in $(seq 1 105); do
    echo "172.16.0.200 - - [$NOW] \"GET /api/data HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"" >> "$NGINX_LOG"
  done
}

ssh_attack() {
  echo ">>> Simulating SSH brute-force (5 failed attempts from 203.0.113.50)"
  for i in $(seq 1 5); do
    echo "$SYSLOG_NOW myhost sshd[$$]: Failed password for root from 203.0.113.50 port 22 ssh2" >> "$AUTH_LOG"
    sleep 0.1
  done
}

sqli() {
  echo ">>> Simulating SQL injection attempt from 198.51.100.10"
  echo "198.51.100.10 - - [$NOW] \"GET /api/users?id=1%20UNION%20SELECT%20*%20FROM%20information_schema HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0\"" >> "$NGINX_LOG"
  echo "198.51.100.10 - - [$NOW] \"GET /search?q=1';DROP%20TABLE%20users-- HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"" >> "$NGINX_LOG"
}

xss() {
  echo ">>> Simulating XSS attempt from 198.51.100.20"
  echo "198.51.100.20 - - [$NOW] \"GET /page?name=%3Cscript%3Ealert('xss')%3C/script%3E HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0\"" >> "$NGINX_LOG"
  echo "198.51.100.20 - - [$NOW] \"GET /search?q=javascript:alert(document.cookie) HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"" >> "$NGINX_LOG"
}

scanner() {
  echo ">>> Simulating scanner user-agent from 45.33.32.156"
  echo "45.33.32.156 - - [$NOW] \"GET / HTTP/1.1\" 200 1024 \"-\" \"sqlmap/1.6 (http://sqlmap.org)\"" >> "$NGINX_LOG"
  echo "45.33.32.156 - - [$NOW] \"GET /admin HTTP/1.1\" 200 512 \"-\" \"Nikto/2.1.6\"" >> "$NGINX_LOG"
  echo "45.33.32.156 - - [$NOW] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"Nuclei - Open-source project\"" >> "$NGINX_LOG"
}

geo_anomaly() {
  echo ">>> Simulating request from foreign IP (Russia — 77.88.55.60 / Yandex)"
  echo "77.88.55.60 - - [$NOW] \"GET / HTTP/1.1\" 200 4096 \"-\" \"Mozilla/5.0\"" >> "$NGINX_LOG"
}

error_5xx() {
  echo ">>> Simulating 5xx spike (4 server errors)"
  for i in $(seq 1 4); do
    echo "8.8.8.8 - - [$NOW] \"GET /api/heavy HTTP/1.1\" 502 0 \"-\" \"Mozilla/5.0\"" >> "$NGINX_LOG"
    sleep 0.1
  done
}

banned_ip() {
  echo ">>> Simulating ban then unban then re-access for 192.168.1.200"
  echo "${F2B_NOW},000 fail2ban.actions        [1234]: NOTICE  [sshd] Ban 192.168.1.200" >> "$F2B_LOG"
  sleep 0.5
  echo "${F2B_NOW},000 fail2ban.actions        [1234]: NOTICE  [sshd] Unban 192.168.1.200" >> "$F2B_LOG"
  sleep 0.5
  echo "192.168.1.200 - - [$NOW] \"GET / HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0\"" >> "$NGINX_LOG"
}

case "$scenario" in
  brute-force) brute_force ;;
  port-scan)   port_scan ;;
  http-flood)  http_flood ;;
  ssh)         ssh_attack ;;
  sqli)        sqli ;;
  xss)         xss ;;
  scanner)     scanner ;;
  geo)         geo_anomaly ;;
  5xx)         error_5xx ;;
  banned)      banned_ip ;;
  all)
    brute_force; sleep 1
    port_scan;   sleep 1
    ssh_attack;  sleep 1
    sqli;        sleep 1
    xss;         sleep 1
    scanner;     sleep 1
    geo_anomaly; sleep 1
    error_5xx;   sleep 1
    banned_ip;   sleep 1
    http_flood
    echo ""
    echo "=== All scenarios injected ==="
    ;;
  *)
    echo "Unknown scenario: $scenario"
    echo "Available: brute-force, port-scan, http-flood, ssh, sqli, xss, scanner, geo, 5xx, banned, all"
    exit 1
    ;;
esac

echo "Done. Check IDPS Agent output for detections."
