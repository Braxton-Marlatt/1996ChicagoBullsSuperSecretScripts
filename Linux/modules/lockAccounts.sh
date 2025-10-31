#!/bin/bash
echo "Locking All Accounts Except Current User"

current_user="$USER"
echo "[+] Current user: $current_user"
echo "------------------"

while IFS=: read -r username _ uid _ _ _ shell; do
    # Skip system accounts (UID < 1000), root, and current user
    if [[ "$username" != "root" && "$username" != "$current_user" && "$uid" -ge 1000 ]]; then
        if [[ "${shell#*"sh"}" != "$shell" ]]; then
            echo "Locking account: $username"
            sudo passwd -l "$username"
        fi
    fi
done < /etc/passwd

echo "[+] All other user accounts have been locked."