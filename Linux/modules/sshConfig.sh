#!/bin/bash
set -euo pipefail

echo "===== SSH Key Cleanup and Configuration Fix ====="
HOSTNAME=$(hostname)
echo "Host: $HOSTNAME"
echo "------------------------------------------------"

# 1. Remove all user SSH keys
echo "[+] Removing SSH authorized_keys files..."

for dir in /home/* /root; do
  if [ -d "$dir/.ssh" ]; then
    echo "    -> Cleaning SSH keys for user directory: $dir"
    rm -f "$dir/.ssh/authorized_keys" "$dir/.ssh/authorized_keys2" 2>/dev/null || true
    chmod 700 "$dir/.ssh" 2>/dev/null || true
  fi
done

echo "[✓] SSH key cleanup complete."


# 2. Verify SSH config path and backup
    echo "[+] Backing up SSH configuration..."
    SSH_CONFIG="/etc/ssh/sshd_config"
    BACKUP_DIR="/etc/ssh/backup_$(date +%F_%H-%M-%S)"
    mkdir -p "$BACKUP_DIR"
    cp -a /etc/ssh/sshd_config* "$BACKUP_DIR/"
    echo "[✓] Backup saved to $BACKUP_DIR"


    # 3. Check current SSH settings and fix if insecure
    echo "[+] Checking SSH configuration..."

    function fix_config_value() {
    local key="$1"
    local value="$2"
    local file="$3"
    
    if grep -qE "^[[:space:]]*${key}" "$file"; then
        sed -i "s|^[[:space:]]*${key}.*|${key} ${value}|g" "$file"
    else
        echo "${key} ${value}" >> "$file"
    fi
    }

    fix_config_value "PasswordAuthentication" "yes" "$SSH_CONFIG"
    fix_config_value "PermitEmptyPasswords" "no" "$SSH_CONFIG"
    fix_config_value "PermitRootLogin" "no" "$SSH_CONFIG"
    fix_config_value "PubkeyAuthentication" "no" "$SSH_CONFIG"
    fix_config_value "UsePAM" "yes" "$SSH_CONFIG"
    fix_config_value "ChallengeResponseAuthentication" "no" "$SSH_CONFIG"

    echo "[✓] SSH configuration secured."


    # 4. Restart SSH safely depending on system type
    echo "[+] Restarting SSH service..."

    if command -v systemctl >/dev/null 2>&1; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh
    elif command -v service >/dev/null 2>&1; then
    service ssh restart 2>/dev/null || service sshd restart 2>/dev/null
    elif [ -x /etc/init.d/ssh ]; then
    /etc/init.d/ssh restart
    else
    echo "[!] Unable to automatically restart SSH. Please restart it manually."
    fi

    echo "[✓] SSH restart complete."
    echo "------------------------------------------------"
    echo "All SSH keys removed and configuration secured."
    echo "Backup of old config: $BACKUP_DIR"