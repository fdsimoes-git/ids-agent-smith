#!/usr/bin/env bash
set -euo pipefail

# IDPS Agent Setup Script for Ubuntu 24 on GCP
# Run as root or with sudo

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="/opt/idps-agent"
LOG_DIR="/var/log/idps-agent"
USER="idps-agent"
GROUP="idps-agent"

echo "=== IDPS Agent Setup ==="

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
mkdir -p /var/lib/idps-agent
chown "$USER:$GROUP" /var/lib/idps-agent
chmod 750 /var/lib/idps-agent

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

# Add idps-agent user to adm group for /var/log/auth.log, /var/log/syslog
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

# Detect nginx before creating any dirs
HAS_NGINX=false
if command -v nginx &>/dev/null; then
  HAS_NGINX=true
fi

# Create nginx deny list file (always — systemd ReadWritePaths requires it to exist)
NGINX_DENY_FILE="/etc/nginx/blocked-ips.conf"
echo "[+] Ensuring nginx deny list file exists: $NGINX_DENY_FILE"
mkdir -p "$(dirname "$NGINX_DENY_FILE")"
if [ ! -f "$NGINX_DENY_FILE" ]; then
  echo "# Managed by idps-agent — do not edit manually" > "$NGINX_DENY_FILE"
fi
chown "$USER:$GROUP" "$NGINX_DENY_FILE"
chmod 644 "$NGINX_DENY_FILE"

# Install Cloudflare real IP config (only if nginx is installed)
if [ "$HAS_NGINX" = true ]; then
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
# Migration: remove old ids-agent sudoers file if it exists
if [ -f /etc/sudoers.d/ids-agent ]; then
  echo "[~] Removing old /etc/sudoers.d/ids-agent sudoers file"
  rm -f /etc/sudoers.d/ids-agent
fi
echo "[+] Configuring sudoers for IDPS actions"
cat > /etc/sudoers.d/idps-agent << 'SUDOERS'
# IDPS Agent — allow blocking/unblocking IPs without password
idps-agent ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client set * banip *
idps-agent ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client set * unbanip *
idps-agent ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client status sshd
idps-agent ALL=(ALL) NOPASSWD: /usr/sbin/iptables -w -C INPUT -s * -j DROP
idps-agent ALL=(ALL) NOPASSWD: /usr/sbin/iptables -w -I INPUT -s * -j DROP
idps-agent ALL=(ALL) NOPASSWD: /usr/sbin/iptables -w -D INPUT -s * -j DROP
idps-agent ALL=(ALL) NOPASSWD: /usr/sbin/iptables -w -S INPUT
idps-agent ALL=(ALL) NOPASSWD: /usr/sbin/ip6tables -w -C INPUT -s * -j DROP
idps-agent ALL=(ALL) NOPASSWD: /usr/sbin/ip6tables -w -I INPUT -s * -j DROP
idps-agent ALL=(ALL) NOPASSWD: /usr/sbin/ip6tables -w -D INPUT -s * -j DROP
idps-agent ALL=(ALL) NOPASSWD: /usr/sbin/ip6tables -w -S INPUT
idps-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload nginx
SUDOERS
chmod 440 /etc/sudoers.d/idps-agent
visudo -c -f /etc/sudoers.d/idps-agent

# 9. Detect available services and configure ReadOnlyPaths accordingly
# This prevents systemd 226/NAMESPACE errors when paths don't exist.
echo ""
echo "=== Service Detection ==="
echo "Checking which services are available on this host..."
echo "(Missing paths in ReadOnlyPaths cause systemd to fail with exit code 226/NAMESPACE)"
echo ""

# Map: service name → log path to check for existence
declare -A SERVICE_CHECKS=(
  [nginx]="/var/log/nginx"
  [fail2ban]="/var/log/fail2ban.log"
  [ufw]="/var/log/ufw.log"
)

ENABLE_NGINX=false
ENABLE_FAIL2BAN=false
ENABLE_UFW=false

for svc in nginx fail2ban ufw; do
  path="${SERVICE_CHECKS[$svc]}"
  if [ -e "$path" ]; then
    detected="detected"
  else
    detected="not found"
  fi

  # In non-interactive environments (cloud-init, Ansible), default to auto-detect
  if [[ -t 0 ]] && [[ -r /dev/tty ]]; then
    while true; do
      if ! read -rp "  Enable $svc log monitoring? ($path — $detected) [y/N]: " answer </dev/tty; then
        answer="n"
        echo ""
        break
      fi
      case "${answer,,}" in
        y|yes) answer="y"; break ;;
        n|no|"") answer="n"; break ;;
        *) echo "    Please answer y or n." ;;
      esac
    done
  else
    # Non-interactive: enable only if the path exists
    if [ -e "$path" ]; then
      answer="y"
      echo "  [auto] $svc monitoring ENABLED ($path exists)"
    else
      answer="n"
      echo "  [auto] $svc monitoring DISABLED ($path not found)"
    fi
  fi

  if [ "$answer" = "y" ]; then
    # Ensure the path exists so ReadOnlyPaths won't trigger 226/NAMESPACE
    if [ ! -e "$path" ]; then
      echo "    [!] $path does not exist — creating it to prevent systemd 226/NAMESPACE failure"
      case "$svc" in
        nginx) mkdir -p "$path" ;;
        *)
          # Create with restrictive perms matching Ubuntu log conventions (root:adm 0640)
          ( umask 0077; : > "$path" )
          chown root:adm "$path" 2>/dev/null || true
          chmod 0640 "$path" 2>/dev/null || true
          ;;
      esac
    fi
    case "$svc" in
      nginx)    ENABLE_NGINX=true ;;
      fail2ban) ENABLE_FAIL2BAN=true ;;
      ufw)      ENABLE_UFW=true ;;
    esac
    echo "    -> $svc monitoring ENABLED"
  else
    echo "    -> $svc monitoring DISABLED (path will be commented out)"
  fi
done
echo ""

# 10. Install systemd service (preserve existing env vars)
echo "[+] Installing systemd service"
LIVE_SERVICE="/etc/systemd/system/idps-agent.service"
OLD_SERVICE="/etc/systemd/system/ids-agent.service"
TEMPLATE="$SCRIPT_DIR/idps-agent.service"

# Migration: if old ids-agent.service exists but new idps-agent.service does not,
# migrate Environment= lines from the old service before installing the new one
if [ ! -f "$LIVE_SERVICE" ] && [ -f "$OLD_SERVICE" ]; then
  echo "[~] Detected old ids-agent.service — migrating environment variables"
  cp "$TEMPLATE" "$LIVE_SERVICE"

  declare -A OLD_ENVS
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*Environment=\"?([^=]+)=(.*) ]]; then
      key="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]}"
      val="${val%\"}"  # strip trailing quote if present
      OLD_ENVS["$key"]="$val"
    fi
  done < "$OLD_SERVICE"

  # Map IDS_* keys to IDPS_* equivalents (e.g. IDS_PORT → IDPS_PORT)
  # IDPS_* values take precedence — only map IDS_* when IDPS_* is not already present
  declare -A MIGRATED_ENVS
  for key in "${!OLD_ENVS[@]}"; do
    val="${OLD_ENVS[$key]}"
    if [[ "$key" == IDS_* ]]; then
      new_key="IDPS_${key#IDS_}"
      if [[ -n "${OLD_ENVS[$new_key]+x}" ]]; then
        echo "[~] Skipping $key → $new_key (explicit $new_key already present)"
      else
        echo "[~] Renaming $key → $new_key"
        MIGRATED_ENVS["$new_key"]="$val"
      fi
    else
      MIGRATED_ENVS["$key"]="$val"
    fi
  done

  # Replace env vars that exist in the template, track matched keys
  declare -A MATCHED_KEYS
  for key in "${!MIGRATED_ENVS[@]}"; do
    val="${MIGRATED_ENVS[$key]}"
    if grep -q "^[[:space:]]*Environment=\"\?${key}=" "$LIVE_SERVICE"; then
      awk -v k="$key" -v v="$val" '{
        if ($0 ~ "^[[:space:]]*Environment=\"?" k "=") print "Environment=\"" k "=" v "\""; else print
      }' "$LIVE_SERVICE" > "${LIVE_SERVICE}.tmp" && mv "${LIVE_SERVICE}.tmp" "$LIVE_SERVICE"
      MATCHED_KEYS["$key"]=1
    fi
  done

  # Carry over any env vars not present in the template
  for key in "${!MIGRATED_ENVS[@]}"; do
    if [[ -z "${MATCHED_KEYS[$key]+x}" ]]; then
      val="${MIGRATED_ENVS[$key]}"
      echo "[~] Carrying over extra env var: $key"
      awk -v k="$key" -v v="$val" '
        /^[[:space:]]*Environment=/ { last=NR }
        { lines[NR]=$0 }
        END {
          for (i=1; i<=NR; i++) {
            print lines[i]
            if (i==last) print "Environment=\"" k "=" v "\""
          }
        }' "$LIVE_SERVICE" > "${LIVE_SERVICE}.tmp" && mv "${LIVE_SERVICE}.tmp" "$LIVE_SERVICE"
    fi
  done

  echo "[~] Migrated environment variables from old ids-agent.service"
  echo "[~] Stopping and disabling old ids-agent service"
  systemctl stop ids-agent 2>/dev/null || true
  systemctl disable ids-agent 2>/dev/null || true

elif [ -f "$LIVE_SERVICE" ]; then
  # Extract Environment= lines from the live service file into an associative array
  declare -A LIVE_ENVS
  while IFS= read -r line; do
    # Match: Environment=KEY=VALUE with optional whitespace and quotes
    if [[ "$line" =~ ^[[:space:]]*Environment=\"?([^=]+)=(.*) ]]; then
      key="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]}"
      val="${val%\"}"  # strip trailing quote if present
      LIVE_ENVS["$key"]="$val"
    fi
  done < "$LIVE_SERVICE"

  # Map IDS_* keys to IDPS_* equivalents (e.g. IDS_PORT → IDPS_PORT)
  # IDPS_* values take precedence — only map IDS_* when IDPS_* is not already present
  declare -A MIGRATED_LIVE_ENVS
  for key in "${!LIVE_ENVS[@]}"; do
    val="${LIVE_ENVS[$key]}"
    if [[ "$key" == IDS_* ]]; then
      new_key="IDPS_${key#IDS_}"
      if [[ -n "${LIVE_ENVS[$new_key]+x}" ]]; then
        echo "[~] Skipping $key → $new_key (explicit $new_key already present)"
      else
        echo "[~] Renaming $key → $new_key"
        MIGRATED_LIVE_ENVS["$new_key"]="$val"
      fi
    else
      MIGRATED_LIVE_ENVS["$key"]="$val"
    fi
  done

  # Start from the template and replace placeholder values with live ones
  cp "$TEMPLATE" "$LIVE_SERVICE"

  # Replace env vars that exist in the template, track matched keys
  declare -A MATCHED_LIVE_KEYS
  for key in "${!MIGRATED_LIVE_ENVS[@]}"; do
    val="${MIGRATED_LIVE_ENVS[$key]}"
    if grep -q "^[[:space:]]*Environment=\"\?${key}=" "$LIVE_SERVICE"; then
      # Use awk for safe replacement (no delimiter conflicts with token values)
      awk -v k="$key" -v v="$val" '{
        if ($0 ~ "^[[:space:]]*Environment=\"?" k "=") print "Environment=\"" k "=" v "\""; else print
      }' "$LIVE_SERVICE" > "${LIVE_SERVICE}.tmp" && mv "${LIVE_SERVICE}.tmp" "$LIVE_SERVICE"
      MATCHED_LIVE_KEYS["$key"]=1
    fi
  done

  # Carry over any env vars not present in the template
  for key in "${!MIGRATED_LIVE_ENVS[@]}"; do
    if [[ -z "${MATCHED_LIVE_KEYS[$key]+x}" ]]; then
      val="${MIGRATED_LIVE_ENVS[$key]}"
      echo "[~] Carrying over extra env var: $key"
      awk -v k="$key" -v v="$val" '
        /^[[:space:]]*Environment=/ { last=NR }
        { lines[NR]=$0 }
        END {
          for (i=1; i<=NR; i++) {
            print lines[i]
            if (i==last) print "Environment=\"" k "=" v "\""
          }
        }' "$LIVE_SERVICE" > "${LIVE_SERVICE}.tmp" && mv "${LIVE_SERVICE}.tmp" "$LIVE_SERVICE"
    fi
  done

  echo "[~] Preserved existing environment variables from live service"
else
  cp "$TEMPLATE" "$LIVE_SERVICE"
  echo "[+] Fresh install — remember to fill in environment variables"
fi

# Uncomment ReadOnlyPaths lines based on user selections
if [ "$ENABLE_NGINX" = true ]; then
  sed -i 's|^#ReadOnlyPaths=/var/log/nginx$|ReadOnlyPaths=/var/log/nginx|' "$LIVE_SERVICE"
fi
if [ "$ENABLE_FAIL2BAN" = true ]; then
  sed -i 's|^#ReadOnlyPaths=/var/log/fail2ban.log$|ReadOnlyPaths=/var/log/fail2ban.log|' "$LIVE_SERVICE"
fi
if [ "$ENABLE_UFW" = true ]; then
  sed -i 's|^#ReadOnlyPaths=/var/log/ufw.log$|ReadOnlyPaths=/var/log/ufw.log|' "$LIVE_SERVICE"
fi

echo "[+] ReadOnlyPaths configured based on detected services"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit /etc/systemd/system/idps-agent.service and fill in your environment variables:"
echo "     - TELEGRAM_BOT_TOKEN"
echo "     - TELEGRAM_CHAT_ID"
echo "     - ANTHROPIC_API_KEY"
echo "     - MONITORED_SERVICE (your app's systemd service name)"
echo "     - API_BEARER_TOKEN"
echo ""
echo "  2. Reload systemd and start:"
echo "     sudo systemctl daemon-reload"
echo "     sudo systemctl enable idps-agent"
echo "     sudo systemctl start idps-agent"
echo ""
echo "  3. Verify it's running:"
echo "     sudo systemctl status idps-agent"
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
