#!/bin/bash
# modules/sshHardening.sh - Comprehensive SSH Server Hardening

set -euo pipefail

echo "=== SSH Server Hardening ==="
HOSTNAME=$(hostname)
echo "Host: $HOSTNAME"
echo "----------------------------------------"

# Configuration variables
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BACKUP="/etc/ssh/sshd_config.backup.$(date +%F_%H-%M-%S)"
SSH_PORT=22
ALLOW_USERS=""
ALLOW_GROUPS=""

# Check if SSH is installed
if ! command -v sshd >/dev/null 2>&1; then
    echo "[!] OpenSSH server not installed. Skipping SSH hardening."
    exit 0
fi

# Backup current configuration
echo "[+] Backing up current SSH configuration..."
sudo cp "$SSHD_CONFIG" "$SSHD_BACKUP"
echo "    Backup saved to: $SSHD_BACKUP"

# Function to safely update sshd_config
update_ssh_setting() {
    local setting="$1"
    local value="$2"
    local config_file="${3:-$SSHD_CONFIG}"
    
    # Remove any existing setting (including commented ones)
    sudo sed -i "/^#\?${setting}/d" "$config_file"
    
    # Add new setting at the end
    echo "${setting} ${value}" | sudo tee -a "$config_file" >/dev/null
}

# Interactive configuration for CCDC
echo ""
echo "[?] SSH Configuration Questions"
echo "    (Press Enter for recommended defaults)"
echo ""

echo ""
echo "[+] Applying SSH hardening configuration..."

# ============================================
# Core Security Settings
# ============================================

# Port configuration
update_ssh_setting "Port" "$SSH_PORT"

# Protocol version
update_ssh_setting "Protocol" "2"

# Address family (IPv4 only for most competitions)
update_ssh_setting "AddressFamily" "inet"

# Listen addresses (optionally restrict)
# update_ssh_setting "ListenAddress" "0.0.0.0"

# ============================================
# Authentication Settings
# ============================================


update_ssh_setting "PermitRootLogin" "no"
echo "    [✓] Root login disabled"


update_ssh_setting "PasswordAuthentication" "yes"
update_ssh_setting "PermitEmptyPasswords" "no"
update_ssh_setting "ChallengeResponseAuthentication" "no"


# Public key authentication
update_ssh_setting "PubkeyAuthentication" "yes"
update_ssh_setting "AuthorizedKeysFile" ".ssh/authorized_keys"

# Disable dangerous authentication methods
update_ssh_setting "HostbasedAuthentication" "no"
update_ssh_setting "IgnoreRhosts" "yes"
update_ssh_setting "PermitUserEnvironment" "no"

# ============================================
# Access Control
# ============================================



# Deny specific users (consider adding common backdoor accounts)
# update_ssh_setting "DenyUsers" "games news uucp proxy"

# ============================================
# Connection Settings
# ============================================

# Login grace time
update_ssh_setting "LoginGraceTime" "30s"

# Maximum authentication attempts
update_ssh_setting "MaxAuthTries" "3"

# Maximum sessions
update_ssh_setting "MaxSessions" "3"

# Maximum simultaneous connections
update_ssh_setting "MaxStartups" "5:50:10"

# Client alive interval (disconnect idle clients)
update_ssh_setting "ClientAliveInterval" "300"
update_ssh_setting "ClientAliveCountMax" "2"

# TCP keepalive
update_ssh_setting "TCPKeepAlive" "yes"

# ============================================
# Disable Unnecessary Features
# ============================================

# X11 forwarding (disable unless needed for GUI apps)
update_ssh_setting "X11Forwarding" "no"

# Agent forwarding
update_ssh_setting "AllowAgentForwarding" "no"

# TCP forwarding (port forwarding)
update_ssh_setting "AllowTcpForwarding" "no"
update_ssh_setting "PermitTunnel" "no"

# Disable SFTP if not needed (comment this out if file transfers required)
# update_ssh_setting "Subsystem" "sftp /usr/lib/openssh/sftp-server"

# Gateway ports
update_ssh_setting "GatewayPorts" "no"

# Permit user RC files
update_ssh_setting "PermitUserRC" "no"

# ============================================
# Cryptography Settings
# ============================================

# Strong ciphers only
update_ssh_setting "Ciphers" "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"

# Strong MACs only
update_ssh_setting "MACs" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"

# Strong key exchange algorithms
update_ssh_setting "KexAlgorithms" "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"

# Host key algorithms
update_ssh_setting "HostKeyAlgorithms" "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256"

# Public key algorithms
update_ssh_setting "PubkeyAcceptedAlgorithms" "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256"

# ============================================
# Logging Settings
# ============================================

# Logging level
update_ssh_setting "LogLevel" "VERBOSE"

# Log to both syslog and auth.log
update_ssh_setting "SyslogFacility" "AUTH"

# ============================================
# Banner and Messages
# ============================================

# Create warning banner
BANNER_FILE="/etc/ssh/banner.txt"
sudo tee "$BANNER_FILE" >/dev/null <<'EOF'
***************************************************************************
                            AUTHORIZED ACCESS ONLY
***************************************************************************
This system is for authorized use only. All activity is logged and 
monitored. Unauthorized access attempts will be prosecuted to the fullest
extent of the law.
***************************************************************************
EOF

update_ssh_setting "Banner" "$BANNER_FILE"

# Disable MOTD
update_ssh_setting "PrintMotd" "no"

# Print last log
update_ssh_setting "PrintLastLog" "yes"

# ============================================
# Additional Hardening
# ============================================

# Strict mode (check file permissions)
update_ssh_setting "StrictModes" "yes"

# Use privilege separation
update_ssh_setting "UsePrivilegeSeparation" "sandbox"

# Use PAM
update_ssh_setting "UsePAM" "yes"

# Compression (disable to prevent CRIME-like attacks)
update_ssh_setting "Compression" "no"

# ============================================
# Validate Configuration
# ============================================

echo ""
echo "[+] Validating SSH configuration..."
if sudo sshd -t -f "$SSHD_CONFIG"; then
    echo "    [✓] Configuration syntax is valid"
else
    echo "    [✗] Configuration has errors!"
    echo "    [!] Restoring backup..."
    sudo cp "$SSHD_BACKUP" "$SSHD_CONFIG"
    echo "    [!] Backup restored. Please review errors above."
    exit 1
fi

# ============================================
# Apply Changes
# ============================================

echo ""
echo "[+] Restarting SSH service..."

# Determine init system and restart SSH
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl restart sshd || sudo systemctl restart ssh
    echo "    [✓] SSH service restarted (systemd)"
elif command -v service >/dev/null 2>&1; then
    sudo service ssh restart || sudo service sshd restart
    echo "    [✓] SSH service restarted (service)"
else
    echo "    [!] Could not restart SSH automatically. Please restart manually."
fi

# ============================================
# Additional Security Measures
# ============================================

echo ""
echo "[+] Applying additional SSH security measures..."

# Set proper permissions on SSH directories
echo "    [+] Setting proper file permissions..."
sudo chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
sudo chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
sudo chmod 644 "$SSHD_CONFIG"

# Ensure .ssh directories have correct permissions for all users
for user_home in /home/* /root; do
    if [[ -d "$user_home/.ssh" ]]; then
        username=$(basename "$user_home")
        echo "    [+] Securing $user_home/.ssh"
        sudo chmod 700 "$user_home/.ssh"
        sudo chmod 600 "$user_home/.ssh/authorized_keys" 2>/dev/null || true
        sudo chmod 600 "$user_home/.ssh/id_*" 2>/dev/null || true
        sudo chmod 644 "$user_home/.ssh/id_*.pub" 2>/dev/null || true
        sudo chmod 644 "$user_home/.ssh/known_hosts" 2>/dev/null || true
        
        # Fix ownership
        if [[ "$user_home" == "/root" ]]; then
            sudo chown -R root:root "$user_home/.ssh"
        else
            sudo chown -R "$username:$username" "$user_home/.ssh" 2>/dev/null || true
        fi
    fi
done

# ============================================
# Firewall Integration
# ============================================

echo ""
echo "[+] Updating firewall rules for SSH..."

# Check which firewall is active
if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -q "Status: active"; then
    # UFW firewall
    if [[ "$SSH_PORT" != "22" ]]; then
        sudo ufw allow "$SSH_PORT/tcp" comment "SSH"
        sudo ufw delete allow 22/tcp 2>/dev/null || true
    else
        sudo ufw allow 22/tcp comment "SSH"
    fi
    echo "    [✓] UFW rules updated"
    
elif command -v firewall-cmd >/dev/null 2>&1 && sudo systemctl is-active --quiet firewalld; then
    # FirewallD
    if [[ "$SSH_PORT" != "22" ]]; then
        sudo firewall-cmd --permanent --add-port="${SSH_PORT}/tcp"
        sudo firewall-cmd --permanent --remove-service=ssh 2>/dev/null || true
    else
        sudo firewall-cmd --permanent --add-service=ssh
    fi
    sudo firewall-cmd --reload
    echo "    [✓] FirewallD rules updated"
    
elif command -v iptables >/dev/null 2>&1; then
    # iptables
    sudo iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --sport "$SSH_PORT" -m conntrack --ctstate ESTABLISHED -j ACCEPT
    echo "    [✓] iptables rules added"
    echo "    [!] Remember to save iptables rules!"
fi

# ============================================
# Rate Limiting with fail2ban
# ============================================

echo ""
echo "[+] Checking fail2ban configuration..."

if command -v fail2ban-client >/dev/null 2>&1; then
    # Create custom SSH jail
    sudo tee /etc/fail2ban/jail.d/sshd-custom.conf >/dev/null <<EOF
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF

    sudo systemctl restart fail2ban 2>/dev/null || sudo service fail2ban restart 2>/dev/null || true
    echo "    [✓] fail2ban configured for SSH"
else
    echo "    [!] fail2ban not installed. Consider installing for brute-force protection:"
    echo "        Debian/Ubuntu: sudo apt install fail2ban"
    echo "        RHEL/CentOS:   sudo yum install fail2ban"
fi

# ============================================
# Generate Security Report
# ============================================

REPORT="/tmp/ssh_hardening_report_$(date +%F_%H-%M-%S).txt"
cat > "$REPORT" <<EOF
SSH Hardening Report
====================
Date: $(date)
Hostname: $HOSTNAME
Backup Location: $SSHD_BACKUP

Configuration Summary:
----------------------
SSH Port: $SSH_PORT
Root Login: $([[ "$DISABLE_ROOT" =~ ^[Yy]$ ]] && echo "Disabled" || echo "Key-only")
Password Auth: $([[ "$DISABLE_PASSWORDS" =~ ^[Yy]$ ]] && echo "Disabled" || echo "Enabled")
Allowed Users: ${ALLOW_USERS:-"All users"}
Allowed Groups: ${ALLOW_GROUPS:-"All groups"}

Active SSH Sessions:
--------------------
$(who | grep -E "pts|tty" || echo "No active sessions")

Recent SSH Login Attempts:
--------------------------
$(sudo grep -i "sshd" /var/log/auth.log 2>/dev/null | tail -20 || echo "Log file not accessible")

Restore Command:
----------------
sudo cp $SSHD_BACKUP $SSHD_CONFIG && sudo systemctl restart sshd

EOF

echo ""
echo "===================================="
echo "[✓] SSH Hardening Complete!"
echo "===================================="
echo ""
echo "Summary:"
echo "  • SSH Port: $SSH_PORT"
echo "  • Root Login: $([[ "$DISABLE_ROOT" =~ ^[Yy]$ ]] && echo "DISABLED" || echo "Keys Only")"
echo "  • Password Auth: $([[ "$DISABLE_PASSWORDS" =~ ^[Yy]$ ]] && echo "DISABLED" || echo "ENABLED")"
echo "  • Backup: $SSHD_BACKUP"
echo "  • Report: $REPORT"
echo ""
echo "IMPORTANT REMINDERS:"
echo "  1. TEST your SSH connection in a NEW terminal before closing this one!"
echo "  2. If locked out, restore with: sudo cp $SSHD_BACKUP $SSHD_CONFIG"
echo "  3. Remember to update your SSH client connection settings if port changed"
echo ""

# Test current connection
echo "[!] Current connection test..."
if [[ -n "$SSH_CONNECTION" ]]; then
    echo "    [!] You are connected via SSH. Keep this terminal open!"
    echo "    [!] Test new connection in a separate terminal before closing this one."
fi

echo "----------------------------------------"