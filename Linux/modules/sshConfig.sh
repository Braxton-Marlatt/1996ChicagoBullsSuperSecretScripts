#!/bin/bash
set -euo pipefail

echo "===== SSH Key Cleanup ====="
HOSTNAME=$(hostname)
echo "Host: $HOSTNAME"
echo "------------------------------------------------"

# Backup directory for old keys
BACKUP_DIR="/root/ssh_key_backup_$(date +%F_%H-%M-%S)"
mkdir -p "$BACKUP_DIR"

# Iterate over all user directories
for dir in /home/* /root; do
    if [ -d "$dir/.ssh" ]; then
        echo "[+] Cleaning SSH keys in $dir"

        # Move any existing authorized_keys files to backup
        for keyfile in "$dir/.ssh/authorized_keys"*; do
            [ -f "$keyfile" ] && mv "$keyfile" "$BACKUP_DIR/" || true
        done

        # Ensure .ssh has correct permissions
        chmod 700 "$dir/.ssh"
        chown "$(basename "$dir")":"$(basename "$dir")" "$dir/.ssh" 2>/dev/null || true
    fi
done

echo "[✓] SSH key cleanup complete."
echo "Backups stored in: $BACKUP_DIR"
echo "------------------------------------------------"
