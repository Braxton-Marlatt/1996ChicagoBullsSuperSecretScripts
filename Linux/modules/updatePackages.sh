#!/bin/bash
echo "Updating System Packages"

# Detect the package manager
if command -v apt >/dev/null 2>&1; then
    echo "[+] Detected Debian/Ubuntu (APT)"
    sudo apt update -y && sudo apt upgrade -y
    sudo apt autoremove -y && sudo apt autoclean -y

elif command -v dnf >/dev/null 2>&1; then
    echo "[+] Detected RHEL/Fedora/Rocky (DNF)"
    sudo dnf upgrade -y
    sudo dnf autoremove -y

elif command -v yum >/dev/null 2>&1; then
    echo "[+] Detected older RHEL/CentOS (YUM)"
    sudo yum update -y
    sudo yum autoremove -y

elif command -v zypper >/dev/null 2>&1; then
    echo "[+] Detected openSUSE (Zypper)"
    sudo zypper refresh
    sudo zypper update -y

elif command -v pacman >/dev/null 2>&1; then
    echo "[+] Detected Arch/Manjaro (Pacman)"
    sudo pacman -Syu --noconfirm

elif command -v apk >/dev/null 2>&1; then
    echo "[+] Detected Alpine Linux (APK)"
    sudo apk update && sudo apk upgrade

else
    echo "[!] Unknown package manager. Cannot update automatically."
    return 1
fi

echo "[✓] System packages updated successfully."
