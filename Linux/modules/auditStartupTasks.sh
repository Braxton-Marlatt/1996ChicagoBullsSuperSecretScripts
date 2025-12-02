#!/bin/bash
echo "Auditing Startup Tasks"
    
echo "[+] Checking systemd enabled services..."
systemctl list-unit-files --state=enabled --no-pager

echo -e "\n[+] Checking /etc/rc.local..."
if [ -f /etc/rc.local ]; then
    cat /etc/rc.local
else
    echo "  [✓] /etc/rc.local not found"
fi

echo -e "\n[+] Checking init.d scripts..."
if [ -d /etc/init.d ]; then
    ls -la /etc/init.d/
fi

echo -e "\n[+] Checking systemd user services..."
for user_home in /home/*; do
    user=$(basename "$user_home")
    if [ -d "$user_home/.config/systemd/user" ]; then
        echo "  User: $user"
        sudo -u "$user" systemctl --user list-unit-files --state=enabled 2>/dev/null
    fi
done

echo -e "\n[+] Checking /etc/profile.d/ scripts..."
if [ -d /etc/profile.d ]; then
    ls -la /etc/profile.d/
fi

echo -e "\n[+] Checking .bashrc and .bash_profile for all users..."
for user_home in /home/* /root; do
    if [ -d "$user_home" ]; then
        echo "  Checking: $user_home"
        grep -H "^[^#]" "$user_home/.bashrc" "$user_home/.bash_profile" 2>/dev/null | grep -v "^$"
    fi
done