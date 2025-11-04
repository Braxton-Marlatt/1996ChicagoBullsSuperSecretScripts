#!/bin/bash

echo "Checking Group Memberships"

echo "[+] Current user's group memberships:"
id

echo "[+] Members of critical groups:"
critical_groups=(sudo wheel adm)

for group in "${critical_groups[@]}"; do
    echo -e "\nMembers of group '$group':"
    getent group "$group"

    # If called with --remove, process removals
    if [[ "$1" == "--remove" ]]; then
        echo "Checking for users to remove from '$group'..."
        members=$(getent group "$group" | awk -F: '{print $4}' | tr ',' ' ')
        for user in $members; do
            # Skip root and the current user
            if [[ "$user" != "root" && "$user" != "$USER" && -n "$user" ]]; then
                read -p "Remove $user from $group? [y/N] " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    sudo gpasswd -d "$user" "$group"
                fi
            fi
        done
    fi
done