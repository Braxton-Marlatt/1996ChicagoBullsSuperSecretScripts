#!/bin/bash

echo "Rotating User Passwords"

HOSTNAME=$(hostname || cat /etc/hostname)
echo -e "HOST: $HOSTNAME"
echo "------------------"

output_file="/root/password_reset_$(date +%F_%H-%M-%S).csv"
echo "username,new_password" > "$output_file"

while IFS=: read -r username _ uid _ _ _ shell; do
    # Only affect users with shells ending in "sh"
    if [[ "${shell#*"sh"}" != "$shell" ]]; then
        # Skip root and system accounts (UID < 1000)
        if [[ "$username" != "root" && "$uid" -ge 1000 ]]; then
            read -sp "Enter new password for $username: " newpass
            echo
            echo "$username,$newpass" | tee -a "$output_file" >/dev/null

            if command -v chpasswd >/dev/null 2>&1; then
                echo "$username:$newpass" | sudo chpasswd
            else
                printf "%s\n%s\n" "$newpass" "$newpass" | sudo passwd "$username"
            fi
        fi
    fi
done < /etc/passwd

chmod 600 "$output_file"
echo "[+] Passwords rotated. Saved to $output_file"