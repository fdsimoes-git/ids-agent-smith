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
cp -r "$SCRIPT_DIR/package.json" "$SCRIPT_DIR/config.js" "$SCRIPT_DIR/src/" "$APP_DIR/"
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

# Ensure UFW log access
if [ -f /var/log/ufw.log ]; then
  setfacl -m u:"$USER":r /var/log/ufw.log 2>/dev/null || chmod o+r /var/log/ufw.log
fi

# 7. Grant journal read access
echo "[+] Granting systemd journal access"
usermod -aG systemd-journal "$USER" 2>/dev/null || true

# 8. Configure sudoers for autonomous actions (fail2ban + ufw)
echo "[+] Configuring sudoers for IDS actions"
cat > /etc/sudoers.d/ids-agent << 'SUDOERS'
# IDS Agent — allow blocking IPs without password
ids-agent ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client set * banip *
ids-agent ALL=(ALL) NOPASSWD: /usr/sbin/ufw deny from *
ids-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload nginx
SUDOERS
chmod 440 /etc/sudoers.d/ids-agent
visudo -c -f /etc/sudoers.d/ids-agent

# 9. Install systemd service
echo "[+] Installing systemd service"
cp "$SCRIPT_DIR/ids-agent.service" /etc/systemd/system/ids-agent.service

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
