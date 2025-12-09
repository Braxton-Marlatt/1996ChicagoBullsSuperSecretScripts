#!/bin/bash

echo -e "\n===== Configuring AppArmor ====="

# Check if AppArmor is installed
if ! command -v aa-status >/dev/null 2>&1; then
    echo "[!] AppArmor not installed. Installing..."
    if command -v apt >/dev/null 2>&1; then
        sudo apt update
        sudo apt install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y apparmor apparmor-utils apparmor-profiles
    else
        echo "[!] Cannot install AppArmor on this system"
        return 1
    fi
fi

# Enable AppArmor service
echo "[+] Enabling AppArmor service..."
sudo systemctl enable apparmor 2>/dev/null
sudo systemctl start apparmor 2>/dev/null

# Check current status
echo -e "\n[+] Current AppArmor status:"
sudo aa-status

# Enable AppArmor on boot (GRUB configuration)
echo -e "\n[+] Ensuring AppArmor starts at boot..."
if [ -f /etc/default/grub ]; then
    # Backup GRUB config
    sudo cp /etc/default/grub /etc/default/grub.backup.$(date +%F_%H-%M-%S)
    
    # Check if AppArmor parameters already exist
    if ! grep -q "apparmor=1" /etc/default/grub; then
        echo "[+] Adding AppArmor to GRUB configuration..."
        sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor /' /etc/default/grub
        sudo update-grub 2>/dev/null || sudo grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null
        echo "    [!] REBOOT REQUIRED for GRUB changes to take effect"
    else
        echo "    [✓] AppArmor already configured in GRUB"
    fi
fi

# Set all profiles to enforce mode
echo -e "\n[+] Setting profiles to enforce mode..."

# Find all profiles in complain mode and enforce them
complain_profiles=$(sudo aa-status --complain 2>/dev/null | grep -v "^[0-9]" | grep "/" | awk '{print $1}')

if [ -n "$complain_profiles" ]; then
    echo "    Profiles in complain mode:"
    echo "$complain_profiles"

    echo "    [+] Automatically enforcing all complain mode profiles..."
    while IFS= read -r profile; do
        if [ -n "$profile" ]; then
            echo "    → Enforcing: $profile"
            sudo aa-enforce "$profile" 2>/dev/null
        fi
    done <<< "$complain_profiles"
else
    echo "    [✓] No profiles in complain mode"
fi

# Load additional profiles
echo -e "\n[+] Loading additional security profiles..."

# Common important profiles to enforce
important_profiles=(
    "/usr/sbin/tcpdump"
    "/usr/bin/man"
    "/usr/sbin/named"
    "/usr/sbin/apache2"
    "/usr/sbin/nginx"
    "/usr/sbin/mysqld"
    "/usr/bin/mysql"
)

for profile in "${important_profiles[@]}"; do
    if [ -f "/etc/apparmor.d${profile}" ] || [ -f "/etc/apparmor.d/usr.sbin.$(basename $profile)" ]; then
        sudo aa-enforce "$profile" 2>/dev/null && echo "    [✓] Enforced: $profile" || true
    fi
done

# Enable additional profile packages if available
if [ -d /usr/share/apparmor/extra-profiles ]; then
    echo -e "\n[+] Loading extra profiles..."
    sudo cp /usr/share/apparmor/extra-profiles/* /etc/apparmor.d/ 2>/dev/null
fi

# Reload all profiles
echo -e "\n[+] Reloading AppArmor profiles..."
sudo systemctl reload apparmor 2>/dev/null || sudo service apparmor reload 2>/dev/null

# Final status
echo -e "\n[+] Final AppArmor Status:"
sudo aa-status

# Generate report
REPORT="/tmp/apparmor_status_$(date +%F_%H-%M-%S).txt"
sudo aa-status > "$REPORT"
echo -e "\n[✓] AppArmor configured. Status saved to: $REPORT"