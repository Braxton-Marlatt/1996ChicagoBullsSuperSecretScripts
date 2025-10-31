#!/usr/bin/env bash
set -euo pipefail

echo "=== Checking and Setting Permissions ==="

# Helper: install a package if possible
_try_install() {
    pkg="$1"
    # Only attempt install if sudo exists and user approves (noninteractive attempt)
    if ! command -v sudo >/dev/null 2>&1; then
        echo "[!] sudo not available — cannot auto-install $pkg"
        return 1
    fi

    if command -v apt >/dev/null 2>&1; then
        echo "[+] Installing $pkg via apt..."
        sudo apt update -y >/dev/null 2>&1 || true
        sudo DEBIAN_FRONTEND=noninteractive apt install -y "$pkg"
        return $?
    elif command -v dnf >/dev/null 2>&1; then
        echo "[+] Installing $pkg via dnf..."
        sudo dnf install -y "$pkg"
        return $?
    elif command -v yum >/dev/null 2>&1; then
        echo "[+] Installing $pkg via yum..."
        sudo yum install -y "$pkg"
        return $?
    elif command -v pacman >/dev/null 2>&1; then
        echo "[+] Installing $pkg via pacman..."
        sudo pacman -Sy --noconfirm "$pkg"
        return $?
    elif command -v zypper >/dev/null 2>&1; then
        echo "[+] Installing $pkg via zypper..."
        sudo zypper --non-interactive install "$pkg"
        return $?
    elif command -v apk >/dev/null 2>&1; then
        echo "[+] Installing $pkg via apk..."
        sudo apk add --no-progress "$pkg"
        return $?
    else
        echo "[!] Unsupported or unknown package manager — cannot auto-install $pkg"
        return 1
    fi
}

# Ensure critical files have correct owner/perms
sudo chown root:shadow /etc/shadow || echo "[!] Failed to chown /etc/shadow (maybe shadow group missing on this system)"
sudo chown root:root   /etc/passwd
sudo chmod 640 /etc/shadow
sudo chmod 644 /etc/passwd

echo
echo "[+] SUID binaries (this may take a while):"
# Restrict to local filesystem to avoid scanning mounted network/dev pseudo FS
sudo find / -xdev -perm -4000 -type f -print 2>/dev/null || true

echo
echo "[+] Directories with 777 permissions (max depth 3):"
sudo find / -xdev -maxdepth 3 -type d -perm -0002 -print 2>/dev/null || true

echo
echo "[+] Files with capabilities:"
if command -v getcap >/dev/null 2>&1; then
    sudo getcap -r / 2>/dev/null || true
else
    echo "    [!] getcap not found."
    # libcap packages differ by distro: libcap2-bin (Debian), libcap (RHEL/CentOS), libcap (Alpine)
    if _try_install "libcap2-bin" || _try_install "libcap" ; then
        echo "    [✓] Installed getcap. Listing capabilities..."
        sudo getcap -r / 2>/dev/null || true
    else
        echo "    [!] Could not install getcap automatically. Install 'libcap2-bin' (Debian/Ubuntu) or 'libcap' (RHEL/Alpine) and re-run."
    fi
fi

echo
echo "[+] Files with extended ACLs in critical directories:"
if command -v getfacl >/dev/null 2>&1; then
    # Use -s to show short output, but some systems' getfacl don't support -s; fall back if needed
    if getfacl -h >/dev/null 2>&1; then
        sudo getfacl -sR /etc /usr /root 2>/dev/null || true
    else
        sudo getfacl -R /etc /usr /root 2>/dev/null || true
    fi
else
    echo "    [!] getfacl not found."
    if _try_install "acl"; then
        echo "    [✓] Installed 'acl'. Listing ACLs..."
        sudo getfacl -sR /etc /usr /root 2>/dev/null || true
    else
        echo "    [!] Could not install 'acl' automatically. On Debian/Ubuntu install package 'acl' (sudo apt install acl) and re-run."
    fi
fi

echo
echo "=== Done ==="
