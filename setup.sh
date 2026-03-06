#!/usr/bin/env bash
set -euo pipefail

# IDS Agent Setup Script for Ubuntu 24 on GCP
# Run as root or with sudo

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="/opt/ids-agent"
LOG_DIR="/var/log/ids-agent"
USER="ids-agent"
GROUP="ids-agent"

echo "=== IDS Agent Setup ==="

# 1. Create system user (no login shell, no home)
if ! id "$USER" &>/dev/null; then
  echo "[+] Creating system user: $USER"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$USER"
else
  echo "[~] User $USER already exists"
fi

# 2. Create log directory
echo "[+] Creating log directory: $LOG_DIR"
mkdir -p "$LOG_DIR"
chown "$USER:$GROUP" "$LOG_DIR"
chmod 750 "$LOG_DIR"

# 3. Create threat history directory
echo "[+] Creating threat history directory"
mkdir -p /var/lib/ids-agent
chown "$USER:$GROUP" /var/lib/ids-agent
chmod 750 /var/lib/ids-agent

# 4. Copy application files
echo "[+] Installing to $APP_DIR"
mkdir -p "$APP_DIR"
cp -r "$SCRIPT_DIR/package.json" "$SCRIPT_DIR/config.js" "$SCRIPT_DIR/src/" "$SCRIPT_DIR/cloudflare-real-ip.conf" "$APP_DIR/"
chown -R "$USER:$GROUP" "$APP_DIR"

# 5. Install Node.js dependencies
echo "[+] Installing Node.js dependencies"
cd "$APP_DIR"
npm install --omit=dev

# 6. Grant read access to log files
echo "[+] Configuring log file permissions"

# Add ids-agent user to adm group for /var/log/auth.log, /var/log/syslog
usermod -aG adm "$USER" 2>/dev/null || true

# Ensure Nginx log access
if [ -d /var/log/nginx ]; then
  setfacl -m u:"$USER":rx /var/log/nginx 2>/dev/null || chmod o+rx /var/log/nginx
  setfacl -m u:"$USER":r /var/log/nginx/access.log 2>/dev/null || chmod o+r /var/log/nginx/access.log
fi

# Ensure fail2ban log access
if [ -f /var/log/fail2ban.log ]; then
  setfacl -m u:"$USER":r /var/log/fail2ban.log 2>/dev/null || chmod o+r /var/log/fail2ban.log
fi

# Create nginx deny list file (always — systemd ReadWritePaths requires it to exist)
NGINX_DENY_FILE="/etc/nginx/blocked-ips.conf"
echo "[+] Ensuring nginx deny list file exists: $NGINX_DENY_FILE"
mkdir -p "$(dirname "$NGINX_DENY_FILE")"
if [ ! -f "$NGINX_DENY_FILE" ]; then
  echo "# Managed by ids-agent — do not edit manually" > "$NGINX_DENY_FILE"
fi
chown "$USER:$GROUP" "$NGINX_DENY_FILE"
chmod 644 "$NGINX_DENY_FILE"

# Install Cloudflare real IP config (only if nginx is installed)
if [ -d /etc/nginx/conf.d ] || [ -d /etc/nginx ]; then
  CF_REAL_IP="/etc/nginx/conf.d/cloudflare-real-ip.conf"
  echo "[+] Installing Cloudflare real IP config: $CF_REAL_IP"
  mkdir -p "$(dirname "$CF_REAL_IP")"
  cp "$SCRIPT_DIR/cloudflare-real-ip.conf" "$CF_REAL_IP"
  chmod 644 "$CF_REAL_IP"
else
  echo "[~] nginx not found — skipping Cloudflare real IP config"
fi

# 7. Grant journal read access
echo "[+] Granting systemd journal access"
usermod -aG systemd-journal "$USER" 2>/dev/null || true

# 8. Configure sudoers for autonomous actions (fail2ban + iptables)
echo "[+] Configuring sudoers for IDS actions"
cat > /etc/sudoers.d/ids-agent << 'SUDOERS'
# IDS Agent — allow blocking/unblocking IPs without password
ids-agent ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client set * banip *
ids-agent ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client set * unbanip *
ids-agent ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client status sshd
ids-agent ALL=(ALL) NOPASSWD: /usr/sbin/iptables -w -C INPUT -s * -j DROP
ids-agent ALL=(ALL) NOPASSWD: /usr/sbin/iptables -w -I INPUT -s * -j DROP
ids-agent ALL=(ALL) NOPASSWD: /usr/sbin/iptables -w -D INPUT -s * -j DROP
ids-agent ALL=(ALL) NOPASSWD: /usr/sbin/iptables -w -S INPUT
ids-agent ALL=(ALL) NOPASSWD: /usr/sbin/ip6tables -w -C INPUT -s * -j DROP
ids-agent ALL=(ALL) NOPASSWD: /usr/sbin/ip6tables -w -I INPUT -s * -j DROP
ids-agent ALL=(ALL) NOPASSWD: /usr/sbin/ip6tables -w -D INPUT -s * -j DROP
ids-agent ALL=(ALL) NOPASSWD: /usr/sbin/ip6tables -w -S INPUT
ids-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload nginx
SUDOERS
chmod 440 /etc/sudoers.d/ids-agent
visudo -c -f /etc/sudoers.d/ids-agent

# 9. Install systemd service (preserve existing env vars)
echo "[+] Installing systemd service"
LIVE_SERVICE="/etc/systemd/system/ids-agent.service"
TEMPLATE="$SCRIPT_DIR/ids-agent.service"

if [ -f "$LIVE_SERVICE" ]; then
  # Extract Environment= lines from the live service file into an associative array
  declare -A LIVE_ENVS
  while IFS= read -r line; do
    # Match: Environment="KEY=VALUE"
    if [[ "$line" =~ ^Environment=\"([^=]+)=(.*)\"$ ]]; then
      LIVE_ENVS["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
    fi
  done < "$LIVE_SERVICE"

  # Start from the template and replace placeholder values with live ones
  cp "$TEMPLATE" "$LIVE_SERVICE"

  for key in "${!LIVE_ENVS[@]}"; do
    val="${LIVE_ENVS[$key]}"
    # Use awk for safe replacement (no delimiter conflicts with token values)
    awk -v k="$key" -v v="$val" '{
      if ($0 ~ "^Environment=\"" k "=") print "Environment=\"" k "=" v "\""; else print
    }' "$LIVE_SERVICE" > "${LIVE_SERVICE}.tmp" && mv "${LIVE_SERVICE}.tmp" "$LIVE_SERVICE"
  done

  echo "[~] Preserved existing environment variables from live service"
else
  cp "$TEMPLATE" "$LIVE_SERVICE"
  echo "[+] Fresh install — remember to fill in environment variables"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit /etc/systemd/system/ids-agent.service and fill in your environment variables:"
echo "     - TELEGRAM_BOT_TOKEN"
echo "     - TELEGRAM_CHAT_ID"
echo "     - ANTHROPIC_API_KEY"
echo "     - MONITORED_SERVICE (your app's systemd service name)"
echo "     - API_BEARER_TOKEN"
echo ""
echo "  2. Reload systemd and start:"
echo "     sudo systemctl daemon-reload"
echo "     sudo systemctl enable ids-agent"
echo "     sudo systemctl start ids-agent"
echo ""
echo "  3. Verify it's running:"
echo "     sudo systemctl status ids-agent"
echo "     curl http://localhost:3001/health"
echo ""
echo "  4. Configure Nginx to log CF-Connecting-IP:"
echo "     Add to nginx.conf http block:"
echo "       log_format cf '\$http_cf_connecting_ip - \$remote_user [\$time_local] \"\$request\" \$status \$body_bytes_sent \"\$http_referer\" \"\$http_user_agent\"';"
echo "       access_log /var/log/nginx/access.log cf;"
echo ""
echo "  5. Enable nginx IP blocking (IMPORTANT):"
echo "     Add inside each nginx server block:"
echo "       include /etc/nginx/blocked-ips.conf;"
echo "     Then reload nginx: sudo systemctl reload nginx"
echo ""
