#!/bin/bash

echo "=== Locking All Accounts Except Current User and a New Admin Account ==="

current_user="$USER"
echo "[+] Current user: $current_user"
echo "----------------------------------------"

# Ask for new admin account to create
read -rp "Enter the username for a NEW admin account to create: " new_admin

# Ensure input is not empty
if [[ -z "$new_admin" ]]; then
    echo "[!] No username entered. Exiting."
    exit 1
fi

# Create the new admin account (if not already present)
if id "$new_admin" &>/dev/null; then
    echo "[+] User '$new_admin' already exists. Skipping creation."
else
    echo "[+] Creating user: $new_admin"
    sudo useradd -m -s /bin/bash "$new_admin"
    sudo passwd "$new_admin"
    sudo usermod -aG sudo "$new_admin" 2>/dev/null || sudo usermod -aG wheel "$new_admin"
    echo "[+] Admin privileges granted to '$new_admin'"
fi

echo ""
echo "[+] Locking all accounts except:"
echo "    - $current_user"
echo "    - $new_admin"
echo "    - root"
echo "----------------------------------------"

# Iterate through /etc/passwd and lock everyone else
while IFS=: read -r username _ uid _ _ _ shell; do

    # Skip:
    # - system users (uid < 1000)
    # - root
    # - current user
    # - newly created admin
    if [[ "$uid" -ge 1000 && "$username" != "root" && "$username" != "$current_user" && "$username" != "$new_admin" ]]; then
        
        # Only lock accounts with a real shell (not nologin, false, etc.)
        if [[ "$shell" == */bash || "$shell" == */sh || "$shell" == */zsh ]]; then
            echo "[-] Locking account: $username"
            sudo passwd -l "$username"
        fi
    fi
done < /etc/passwd

echo ""
echo "[✓] All other user accounts have been locked."
echo "----------------------------------------"
echo "Allowed accounts:"
echo "  • root"
echo "  • $current_user"
echo "  • $new_admin"
