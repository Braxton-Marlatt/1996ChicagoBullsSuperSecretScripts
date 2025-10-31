#!/bin/bash

set -euo pipefail

echo "===== SYSTEM PERMISSIONS AUDIT ====="
HOSTNAME=$(hostname)
echo "Host: $HOSTNAME"
echo "------------------------------------"


# ---------- [1] Check /etc/passwd and /etc/shadow ----------
echo "[+] Checking critical file permissions..."

declare -A files=(
["/etc/passwd"]="root:root 644"
["/etc/shadow"]="root:shadow 640"
["/etc/group"]="root:root 644"
["/etc/gshadow"]="root:shadow 640"
)

for file in "${!files[@]}"; do
if [ -e "$file" ]; then
    expected_owner=$(echo "${files[$file]}" | awk '{print $1}')
    expected_perms=$(echo "${files[$file]}" | awk '{print $2}')

    actual_owner=$(stat -c "%U:%G" "$file")
    actual_perms=$(stat -c "%a" "$file")

    echo "    → $file"
    echo "      Current: owner=$actual_owner perms=$actual_perms"
    echo "      Expected: owner=$expected_owner perms=$expected_perms"

    # Fix mismatched permissions or ownership
    if [ "$actual_owner" != "$expected_owner" ]; then
    echo "      [!] Fixing ownership..."
    sudo chown "$expected_owner" "$file"
    fi

    if [ "$actual_perms" != "$expected_perms" ]; then
    echo "      [!] Fixing permissions..."
    sudo chmod "$expected_perms" "$file"
    fi
else
    echo "      [!] Missing: $file (check system integrity)"
fi
done

echo "[✓] File permission check complete."
echo


# ---------- [2] Find SUID/SGID binaries ----------
echo "[+] Searching for SUID and SGID binaries..."
sudo find / -perm /6000 -type f 2>/dev/null | tee /tmp/suid_sgid_list.txt
echo "[✓] Results saved to /tmp/suid_sgid_list.txt"
echo


# ---------- [3] Check world-writable directories ----------
echo "[+] Checking for world-writable directories (depth ≤ 3)..."
sudo find / -maxdepth 3 -type d -perm -0002 2>/dev/null | tee /tmp/world_writable_dirs.txt
echo "[✓] Results saved to /tmp/world_writable_dirs.txt"
echo


# ---------- [4] Check capabilities ----------
if command -v getcap >/dev/null 2>&1; then
echo "[+] Checking for files with Linux capabilities..."
sudo getcap -r / 2>/dev/null | tee /tmp/file_capabilities.txt
echo "[✓] Results saved to /tmp/file_capabilities.txt"
else
echo "[!] 'getcap' not installed — skipping capabilities check."
fi
echo


# ---------- [5] Check for extended ACLs ----------
if command -v getfacl >/dev/null 2>&1; then
echo "[+] Checking for files with extended ACLs in critical dirs..."
sudo getfacl -sR /etc/ /usr/ /root/ 2>/dev/null | grep -B1 "user:" | tee /tmp/acl_check.txt
echo "[✓] ACL report saved to /tmp/acl_check.txt"
else
echo "[!] 'getfacl' not installed — skipping ACL check."
fi
echo

echo "------------------------------------"
echo "[✓] Permissions audit completed."
echo "Reports:"
echo "  • /tmp/suid_sgid_list.txt"
echo "  • /tmp/world_writable_dirs.txt"
echo "  • /tmp/file_capabilities.txt"
echo "  • /tmp/acl_check.txt"
echo "------------------------------------"