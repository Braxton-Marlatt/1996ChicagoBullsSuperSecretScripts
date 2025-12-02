#!/bin/bash
echo "Verifying Package Integrity"

if command -v apt >/dev/null 2>&1; then
    echo "[+] Detected Debian/Ubuntu system"
    if ! command -v debsums >/dev/null 2>&1; then
        echo "[+] Installing debsums..."
        sudo apt update -y >/dev/null 2>&1
        sudo apt install -y debsums >/dev/null 2>&1
    fi
    echo "[+] Running debsums to verify installed package checksums..."
    sudo debsums -s || echo "[!] Some package files failed integrity check."
    echo "[✓] debsums verification complete."

elif command -v rpm >/dev/null 2>&1; then
    echo "[+] Detected RHEL/Fedora/Rocky system"
    echo "[+] Running rpm --verify..."
    sudo rpm -Va | tee /tmp/rpm_verify_report.txt
    echo "[✓] rpm integrity report saved to /tmp/rpm_verify_report.txt"

elif command -v pacman >/dev/null 2>&1; then
    echo "[+] Detected Arch/Manjaro system"
    echo "[+] Running pacman -Qkk (package file verification)..."
    sudo pacman -Qkk | tee /tmp/pacman_verify_report.txt
    echo "[✓] pacman integrity report saved to /tmp/pacman_verify_report.txt"

elif command -v zypper >/dev/null 2>&1; then
    echo "[+] Detected openSUSE system"
    echo "[+] Using rpm verification via zypper..."
    sudo rpm -Va | tee /tmp/zypper_rpm_verify.txt
    echo "[✓] Integrity report saved to /tmp/zypper_rpm_verify.txt"

elif command -v apk >/dev/null 2>&1; then
    echo "[+] Detected Alpine Linux system"
    echo "[+] Verifying installed package checksums..."
    sudo apk verify | tee /tmp/apk_verify_report.txt
    echo "[✓] Integrity report saved to /tmp/apk_verify_report.txt"

else
    echo "[!] Could not detect supported package manager for integrity check."
fi

echo "------------------------------------"
echo "[✓] Package integrity verification completed."
