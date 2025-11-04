#!/bin/bash
# modules/fail2banSetup.sh - Fail2ban Installation and Configuration

set -euo pipefail

echo "=== Fail2ban Setup and Configuration ==="
HOSTNAME=$(hostname)
echo "Host: $HOSTNAME"
echo "----------------------------------------"

# ============================================
# Configuration Variables
# ============================================
FAIL2BAN_CONFIG_DIR="/etc/fail2ban"
FAIL2BAN_JAIL_LOCAL="$FAIL2BAN_CONFIG_DIR/jail.local"
FAIL2BAN_CUSTOM_JAILS="$FAIL2BAN_CONFIG_DIR/jail.d"

# Default settings (adjust for competition)
DEFAULT_BANTIME=3600          # 1 hour
DEFAULT_FINDTIME=600          # 10 minutes
DEFAULT_MAXRETRY=3            # 3 attempts
SSH_PORT=22                   # Adjust if SSH port changed

# ============================================
# Helper Functions
# ============================================

install_fail2ban() {
    echo "[+] Installing fail2ban..."
    
    if command -v apt >/dev/null 2>&1; then
        sudo apt update
        sudo DEBIAN_FRONTEND=noninteractive apt install -y fail2ban
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y fail2ban fail2ban-systemd
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y fail2ban fail2ban-systemd
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y fail2ban
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm fail2ban
    elif command -v apk >/dev/null 2>&1; then
        sudo apk add --no-cache fail2ban
    else
        echo "[!] Unsupported package manager. Please install fail2ban manually."
        exit 1
    fi
    
    echo "    [✓] fail2ban installed"
}

# ============================================
# Check and Install fail2ban
# ============================================

if ! command -v fail2ban-client >/dev/null 2>&1; then
    echo "[!] fail2ban not found"
    read -p "Install fail2ban? (Y/n): " install_choice
    if [[ ! "$install_choice" =~ ^[Nn]$ ]]; then
        install_fail2ban
    else
        echo "[!] Skipping fail2ban setup"
        exit 0
    fi
else
    echo "[✓] fail2ban is already installed"
fi

# ============================================
# Backup Existing Configuration
# ============================================

echo "[+] Backing up existing configuration..."
if [[ -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
    sudo cp "$FAIL2BAN_JAIL_LOCAL" "${FAIL2BAN_JAIL_LOCAL}.backup.$(date +%F_%H-%M-%S)"
    echo "    [✓] Backed up jail.local"
fi

# ============================================
# Create Main jail.local Configuration
# ============================================

echo "[+] Creating main fail2ban configuration..."

sudo tee "$FAIL2BAN_JAIL_LOCAL" >/dev/null <<EOF
# Fail2ban Main Configuration
# Generated: $(date)

[DEFAULT]
# Ban settings
bantime  = ${DEFAULT_BANTIME}
findtime = ${DEFAULT_FINDTIME}
maxretry = ${DEFAULT_MAXRETRY}

# Destination email for notifications (set your email)
destemail = root@localhost
sender = fail2ban@$(hostname)

# Action to take (ban and send email)
action = %(action_mwl)s

# Ignore localhost
ignoreip = 127.0.0.1/8 ::1

# Ban action (use appropriate firewall)
banaction = iptables-multiport
# For systems using firewalld:
# banaction = firewallcmd-ipset

# Log settings
logtarget = /var/log/fail2ban.log
loglevel = INFO
syslogsocket = auto

# Database
dbfile = /var/lib/fail2ban/fail2ban.sqlite3
dbpurgeage = 86400
EOF

echo "    [✓] Main configuration created"

# ============================================
# SSH Jail Configuration
# ============================================

echo "[+] Configuring SSH protection..."

sudo tee "$FAIL2BAN_CUSTOM_JAILS/sshd-custom.conf" >/dev/null <<EOF
# SSH Brute Force Protection
[sshd]
enabled  = true
port     = $SSH_PORT
filter   = sshd
logpath  = /var/log/auth.log
          /var/log/secure
maxretry = 3
bantime  = 3600
findtime = 600

# More aggressive banning for repeat offenders
[sshd-aggressive]
enabled  = true
port     = $SSH_PORT
filter   = sshd
logpath  = /var/log/auth.log
          /var/log/secure
maxretry = 2
bantime  = 86400
findtime = 3600

# Ban hosts that do too many connections
[sshd-ddos]
enabled  = true
port     = $SSH_PORT
filter   = sshd-ddos
logpath  = /var/log/auth.log
          /var/log/secure
maxretry = 10
bantime  = 600
findtime = 60
EOF

echo "    [✓] SSH protection configured"

# ============================================
# Web Server Jails
# ============================================

echo "[+] Configuring web server protection..."

sudo tee "$FAIL2BAN_CUSTOM_JAILS/web-servers.conf" >/dev/null <<EOF
# Apache Authentication Failures
[apache-auth]
enabled  = false
port     = http,https
filter   = apache-auth
logpath  = /var/log/apache*/*error.log
          /var/log/httpd/*error.log
maxretry = 5

# Apache Bad Bots
[apache-badbots]
enabled  = false
port     = http,https
filter   = apache-badbots
logpath  = /var/log/apache*/*access.log
          /var/log/httpd/*access.log
maxretry = 2

# Apache DoS Protection
[apache-overflows]
enabled  = false
port     = http,https
filter   = apache-overflows
logpath  = /var/log/apache*/*error.log
          /var/log/httpd/*error.log
maxretry = 2

# Nginx Authentication Failures
[nginx-http-auth]
enabled  = false
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 5

# Nginx Bad Bots
[nginx-badbots]
enabled  = false
port     = http,https
filter   = nginx-badbots
logpath  = /var/log/nginx/access.log
maxretry = 2

# Nginx DoS Protection
[nginx-limit-req]
enabled  = false
port     = http,https
filter   = nginx-limit-req
logpath  = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime  = 600
EOF

# Enable if Apache/Nginx detected
if systemctl is-active --quiet apache2 || systemctl is-active --quiet httpd; then
    sudo sed -i 's/\[apache-auth\]/[apache-auth]/; /\[apache-auth\]/,/^\[/ s/enabled  = false/enabled  = true/' "$FAIL2BAN_CUSTOM_JAILS/web-servers.conf"
    sudo sed -i 's/\[apache-badbots\]/[apache-badbots]/; /\[apache-badbots\]/,/^\[/ s/enabled  = false/enabled  = true/' "$FAIL2BAN_CUSTOM_JAILS/web-servers.conf"
    echo "    [✓] Apache protection enabled"
fi

if systemctl is-active --quiet nginx; then
    sudo sed -i 's/\[nginx-http-auth\]/[nginx-http-auth]/; /\[nginx-http-auth\]/,/^\[/ s/enabled  = false/enabled  = true/' "$FAIL2BAN_CUSTOM_JAILS/web-servers.conf"
    sudo sed -i 's/\[nginx-badbots\]/[nginx-badbots]/; /\[nginx-badbots\]/,/^\[/ s/enabled  = false/enabled  = true/' "$FAIL2BAN_CUSTOM_JAILS/web-servers.conf"
    echo "    [✓] Nginx protection enabled"
fi

# ============================================
# FTP/Mail/Database Jails
# ============================================

echo "[+] Configuring additional service protection..."

sudo tee "$FAIL2BAN_CUSTOM_JAILS/other-services.conf" >/dev/null <<EOF
# FTP Protection
[vsftpd]
enabled  = false
port     = ftp,ftp-data,ftps,ftps-data
filter   = vsftpd
logpath  = /var/log/vsftpd.log
maxretry = 3

[proftpd]
enabled  = false
port     = ftp,ftp-data,ftps,ftps-data
filter   = proftpd
logpath  = /var/log/proftpd/proftpd.log
maxretry = 3

# Mail Server Protection
[postfix]
enabled  = false
port     = smtp,465,submission
filter   = postfix
logpath  = /var/log/mail.log
          /var/log/maillog
maxretry = 5

[dovecot]
enabled  = false
port     = pop3,pop3s,imap,imaps,submission,465,sieve
filter   = dovecot
logpath  = /var/log/mail.log
          /var/log/maillog
maxretry = 5

# MySQL/MariaDB Protection
[mysqld-auth]
enabled  = false
port     = 3306
filter   = mysqld-auth
logpath  = /var/log/mysql/error.log
          /var/log/mysqld.log
maxretry = 5

# PostgreSQL Protection
[postgresql]
enabled  = false
port     = 5432
filter   = postgresql
logpath  = /var/log/postgresql/postgresql-*-main.log
maxretry = 5

# DNS Protection (BIND)
[named-refused]
enabled  = false
port     = domain,953
filter   = named-refused
logpath  = /var/log/named/security.log
maxretry = 10
EOF

# Auto-enable based on running services
for service in vsftpd proftpd postfix dovecot mysqld mariadb postgresql named; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        case "$service" in
            mysqld|mariadb)
                sudo sed -i "/\[mysqld-auth\]/,/^\[/ s/enabled  = false/enabled  = true/" "$FAIL2BAN_CUSTOM_JAILS/other-services.conf"
                ;;
            named)
                sudo sed -i "/\[named-refused\]/,/^\[/ s/enabled  = false/enabled  = true/" "$FAIL2BAN_CUSTOM_JAILS/other-services.conf"
                ;;
            *)
                sudo sed -i "/\[$service\]/,/^\[/ s/enabled  = false/enabled  = true/" "$FAIL2BAN_CUSTOM_JAILS/other-services.conf"
                ;;
        esac
        echo "    [✓] $service protection enabled"
    fi
done

# ============================================
# Custom Filters (if needed)
# ============================================

echo "[+] Creating custom filters..."

# SSH DDOS filter (if doesn't exist)
if [[ ! -f "$FAIL2BAN_CONFIG_DIR/filter.d/sshd-ddos.conf" ]]; then
    sudo tee "$FAIL2BAN_CONFIG_DIR/filter.d/sshd-ddos.conf" >/dev/null <<'EOF'
# Fail2ban filter for SSH DDOS
[Definition]
failregex = ^.*sshd\[\d+\]: Did not receive identification string from <HOST>
            ^.*sshd\[\d+\]: Connection closed by <HOST> port \d+ \[preauth\]
            ^.*sshd\[\d+\]: Connection reset by <HOST> port \d+ \[preauth\]
ignoreregex =
EOF
    echo "    [✓] SSH DDOS filter created"
fi

# ============================================
# Whitelist Management
# ============================================

echo ""
read -p "Add IP addresses to whitelist? (y/N): " add_whitelist
if [[ "$add_whitelist" =~ ^[Yy]$ ]]; then
    read -p "Enter IPs to whitelist (space-separated): " whitelist_ips
    if [[ -n "$whitelist_ips" ]]; then
        for ip in $whitelist_ips; do
            if ! grep -q "ignoreip.*$ip" "$FAIL2BAN_JAIL_LOCAL"; then
                sudo sed -i "/ignoreip =/ s/$/ $ip/" "$FAIL2BAN_JAIL_LOCAL"
                echo "    [✓] Whitelisted: $ip"
            fi
        done
    fi
fi

# ============================================
# Start and Enable fail2ban
# ============================================

echo ""
echo "[+] Starting fail2ban service..."

if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl enable fail2ban
    sudo systemctl restart fail2ban
    echo "    [✓] fail2ban enabled and started (systemd)"
elif command -v service >/dev/null 2>&1; then
    sudo service fail2ban restart
    sudo chkconfig fail2ban on 2>/dev/null || true
    echo "    [✓] fail2ban enabled and started (service)"
else
    echo "    [!] Could not start fail2ban automatically"
fi

# Wait for fail2ban to initialize
sleep 2

# ============================================
# Verify Configuration
# ============================================

echo ""
echo "[+] Verifying fail2ban status..."

if command -v fail2ban-client >/dev/null 2>&1; then
    echo ""
    echo "Active Jails:"
    sudo fail2ban-client status | grep "Jail list" || echo "    No active jails"
    
    echo ""
    echo "SSH Jail Status:"
    sudo fail2ban-client status sshd 2>/dev/null || echo "    SSH jail not active"
fi

# ============================================
# Create Management Script
# ============================================

echo ""
echo "[+] Creating fail2ban management script..."

sudo tee /usr/local/bin/fail2ban-manage >/dev/null <<'EOFSCRIPT'
#!/bin/bash
# Fail2ban Management Script

case "$1" in
    status)
        echo "=== Fail2ban Status ==="
        fail2ban-client status
        ;;
    banned)
        echo "=== Currently Banned IPs ==="
        for jail in $(fail2ban-client status | grep "Jail list" | sed 's/.*://; s/,//g'); do
            echo ""
            echo "[$jail]"
            fail2ban-client status "$jail" | grep "Banned IP list"
        done
        ;;
    unban)
        if [[ -z "$2" ]]; then
            echo "Usage: $0 unban <IP_ADDRESS>"
            exit 1
        fi
        echo "Unbanning $2 from all jails..."
        fail2ban-client unban "$2"
        echo "Done"
        ;;
    unban-all)
        echo "Unbanning all IPs from all jails..."
        for jail in $(fail2ban-client status | grep "Jail list" | sed 's/.*://; s/,//g'); do
            fail2ban-client set "$jail" unbanip --all
        done
        echo "Done"
        ;;
    stats)
        echo "=== Fail2ban Statistics ==="
        for jail in $(fail2ban-client status | grep "Jail list" | sed 's/.*://; s/,//g'); do
            echo ""
            echo "[$jail]"
            fail2ban-client status "$jail"
        done
        ;;
    log)
        tail -f /var/log/fail2ban.log
        ;;
    *)
        echo "Fail2ban Management Script"
        echo ""
        echo "Usage: $0 {status|banned|unban|unban-all|stats|log}"
        echo ""
        echo "Commands:"
        echo "  status      - Show fail2ban service status"
        echo "  banned      - List all currently banned IPs"
        echo "  unban <IP>  - Unban a specific IP address"
        echo "  unban-all   - Unban all IPs from all jails"
        echo "  stats       - Show detailed statistics for all jails"
        echo "  log         - Tail fail2ban log file"
        exit 1
        ;;
esac
EOFSCRIPT

sudo chmod +x /usr/local/bin/fail2ban-manage
echo "    [✓] Management script created: /usr/local/bin/fail2ban-manage"

# ============================================
# Generate Report
# ============================================

REPORT="/tmp/fail2ban_setup_$(date +%F_%H-%M-%S).txt"
cat > "$REPORT" <<EOF
Fail2ban Setup Report
=====================
Date: $(date)
Hostname: $HOSTNAME

Configuration:
--------------
Ban Time: ${DEFAULT_BANTIME}s
Find Time: ${DEFAULT_FINDTIME}s
Max Retry: ${DEFAULT_MAXRETRY}

Active Jails:
-------------
$(sudo fail2ban-client status 2>/dev/null || echo "Service not responding")

Management Commands:
--------------------
Status:        fail2ban-manage status
Banned IPs:    fail2ban-manage banned
Unban IP:      fail2ban-manage unban <IP>
Unban All:     fail2ban-manage unban-all
Statistics:    fail2ban-manage stats
Watch Log:     fail2ban-manage log

Manual Commands:
----------------
Check jail:    fail2ban-client status <jail_name>
Ban IP:        fail2ban-client set <jail_name> banip <IP>
Reload:        fail2ban-client reload

Configuration Files:
--------------------
Main Config:   $FAIL2BAN_JAIL_LOCAL
Custom Jails:  $FAIL2BAN_CUSTOM_JAILS/
Filters:       $FAIL2BAN_CONFIG_DIR/filter.d/
Log File:      /var/log/fail2ban.log
EOF

echo ""
echo "===================================="
echo "[✓] Fail2ban Setup Complete!"
echo "===================================="
echo ""
echo "Report saved to: $REPORT"
echo ""
echo "Quick Commands:"
echo "  • Check status:  fail2ban-manage status"
echo "  • View banned:   fail2ban-manage banned"
echo "  • Watch logs:    fail2ban-manage log"
echo ""
echo "Fail2ban is now protecting:"
sudo fail2ban-client status | grep "Jail list" || echo "  No jails active yet"
echo ""
echo "----------------------------------------"