#!/usr/bin/env bash

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[38;5;208m'
AQUA='\033[38;5;45m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

function print_banner {
    echo -e "${CYAN}"
    echo "================================================"
    echo "   $1"
    echo "================================================"
    echo -e "${NC}"
}

function _log_with_color {
    local level="$1"
    local color="$2"
    shift 2 || true

    if ! __log_should_emit "$level"; then
        return 0
    fi

    printf '%b[%s]%b %s - %s\n' "$color" "$level" "$NC" "$(date +"%Y-%m-%d %H:%M:%S")" "$*"
}

function log_warning {
    _log_with_color "WARNING" "$ORANGE" "$@"
}

function log_info {
    _log_with_color "INFO" "$AQUA" "$@"
}

function checkPermissions {
    echo "Checking and Setting Permissions"

    sudo chown root:shadow /etc/shadow
    sudo chown root:root /etc/passwd
    sudo chmod 640 /etc/shadow
    sudo chmod 644 /etc/passwd

    echo "[+] SUID binaries:"
    sudo find / -perm -4000 2>/dev/null

    echo "[+] Directories with 777 permissions (max depth 3):"
    sudo find / -maxdepth 3 -type d -perm -777 2>/dev/null

    echo "[+] Files with capabilities:"
    sudo getcap -r / 2>/dev/null

    echo "[+] Files with extended ACLs in critical directories:"
    sudo getfacl -sR /etc/ /usr/ /root/
}

function bulkDisableServices {
  # Bulk disable services
  echo -e "\e[33mDisabling unneeded services\e[0m"
  systemctl stop xinetd
  systemctl disable xinetd
  systemctl stop rexec
  systemctl disable rexec
  systemctl stop rsh
  systemctl disable rsh
  systemctl stop rlogin
  systemctl disable rlogin
  systemctl stop ypbind
  systemctl disable ypbind
  systemctl stop tftp
  systemctl disable tftp
  systemctl stop certmonger
  systemctl disable certmonger
  systemctl stop cgconfig
  systemctl disable cgconfig
  systemctl stop cgred
  systemctl disable cgred
  systemctl stop cpuspeed
  systemctl disable cpuspeed
  systemctl enable irqbalance
  systemctl stop kdump
  systemctl disable kdump
  systemctl stop mdmonitor
  systemctl disable mdmonitor
  systemctl stop messagebus
  systemctl disable messagebus
  systemctl stop netconsole
  systemctl disable netconsole
  systemctl stop ntpdate
  systemctl disable ntpdate
  systemctl stop oddjobd
  systemctl disable oddjobd
  systemctl stop portreserve
  systemctl disable portreserve
  systemctl enable psacct
  systemctl stop qpidd
  systemctl disable qpidd
  systemctl stop quota_nld
  systemctl disable quota_nld
  systemctl stop rdisc
  systemctl disable rdisc
  systemctl stop rhnsd
  systemctl disable rhnsd
  systemctl stop rhsmcertd
  systemctl disable rhsmcertd
  systemctl stop saslauthd
  systemctl disable saslauthd
  systemctl stop smartd
  systemctl disable smartd
  systemctl stop sysstat
  systemctl disable sysstat
  systemctl enable crond
  systemctl stop atd
  systemctl disable atd
  systemctl stop nfslock
  systemctl disable nfslock
  systemctl stop named
  systemctl disable named
  systemctl stop dovecot
  systemctl disable dovecot
  systemctl stop squid
  systemctl disable squid
  systemctl stop snmpd
  systemctl disable snmpd
  systemctl stop postfix
  systemctl disable postfix

  # Disable rpc
  echo -e "\e[33mDisabling rpc services\e[0m"
  systemctl disable rpcgssd
  systemctl disable rpcgssd
  systemctl disable rpcsvcgssd
  systemctl disable rpcsvcgssd
  systemctl disable rpcbind
  systemctl disable rpcidmapd

  # Disable Network File Systems (netfs)
  echo -e "\e[33mDisabling netfs\e[0m"
  systemctl stop netfs
  systemctl disable netfs

  # Disable Network File System (nfs)
  echo -e "\e[33mDisabling nfs\e[0m"
  systemctl stop nfs
  systemctl disable nfs

  #Disable CUPS (Internet Printing Protocol service), has a lot of exploits, disable it
  echo -e "\e[33mDisabling CUPS\e[0m"
  systemctl stop cups
  systemctl disable cups
}

function hardenIPtables {
    # Empty all rules
    iptables -t filter -F
    iptables -t filter -X
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT    
    
    iptables -A OUTPUT -p icmp -m conntrack --ctstate NEW -j ACCEPT


    # Block everything by default
    iptables -t filter -P INPUT DROP
    iptables -t filter -P FORWARD DROP
    iptables -t filter -P OUTPUT DROP

    # Allow inbound packets that are part of established connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT


    # Allow loopback communications
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow essential services
    # DNS
    iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
    
    # HTTP / HTTPS
    iptables -A OUTPUT -p tcp --dport 80  -m conntrack --ctstate NEW -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
    }

function setupSELinux {
    echo -e "\e[33mEnabling SELinux\e[0m"
    setenforce true
    echo -e "\e[33mRunning restorecon /\e[0m"
    restorecon -R /

    cp /etc/selinux/config /etc/selinux/.config_backup1
    echo "SELINUX=enforcing" >> /etc/selinux/config

    sestatus
}

function setupAppArmor {
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
        
        read -p "    Enforce all complain mode profiles? [y/N] " enforce_confirm
        if [[ "$enforce_confirm" =~ ^[Yy]$ ]]; then
            while IFS= read -r profile; do
                if [ -n "$profile" ]; then
                    echo "    → Enforcing: $profile"
                    sudo aa-enforce "$profile" 2>/dev/null
                fi
            done <<< "$complain_profiles"
        fi
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
}


function sudoCheck {
    print_banner "Checking Sudo Privileges"

    echo "[+] Current user's sudo privileges:"
    sudo -l

    echo "[+] Users with sudo privileges:"
    sudo getent group sudo
    sudo getent group wheel
}

function groupMemberships {
    print_banner "Checking Group Memberships"

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
}

function rotatePasswords {
    print_banner "Rotating User Passwords"

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
                newpass=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 15)
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
}

function sshConfig {
    set -euo pipefail

echo "===== SSH Key Cleanup and Configuration Fix ====="
HOSTNAME=$(hostname)
echo "Host: $HOSTNAME"
echo "------------------------------------------------"

# 1. Remove all user SSH keys
echo "[+] Removing SSH authorized_keys files..."

for dir in /home/* /root; do
  if [ -d "$dir/.ssh" ]; then
    echo "    -> Cleaning SSH keys for user directory: $dir"
    rm -f "$dir/.ssh/authorized_keys" "$dir/.ssh/authorized_keys2" 2>/dev/null || true
    chmod 700 "$dir/.ssh" 2>/dev/null || true
  fi
done

echo "[✓] SSH key cleanup complete."


# 2. Verify SSH config path and backup
    echo "[+] Backing up SSH configuration..."
    SSH_CONFIG="/etc/ssh/sshd_config"
    BACKUP_DIR="/etc/ssh/backup_$(date +%F_%H-%M-%S)"
    mkdir -p "$BACKUP_DIR"
    cp -a /etc/ssh/sshd_config* "$BACKUP_DIR/"
    echo "[✓] Backup saved to $BACKUP_DIR"


    # 3. Check current SSH settings and fix if insecure
    echo "[+] Checking SSH configuration..."

    function fix_config_value() {
    local key="$1"
    local value="$2"
    local file="$3"
    
    if grep -qE "^[[:space:]]*${key}" "$file"; then
        sed -i "s|^[[:space:]]*${key}.*|${key} ${value}|g" "$file"
    else
        echo "${key} ${value}" >> "$file"
    fi
    }

    fix_config_value "PasswordAuthentication" "yes" "$SSH_CONFIG"
    fix_config_value "PermitEmptyPasswords" "no" "$SSH_CONFIG"
    fix_config_value "PermitRootLogin" "no" "$SSH_CONFIG"
    fix_config_value "PubkeyAuthentication" "no" "$SSH_CONFIG"
    fix_config_value "UsePAM" "yes" "$SSH_CONFIG"
    fix_config_value "ChallengeResponseAuthentication" "no" "$SSH_CONFIG"

    echo "[✓] SSH configuration secured."


    # 4. Restart SSH safely depending on system type
    echo "[+] Restarting SSH service..."

    if command -v systemctl >/dev/null 2>&1; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh
    elif command -v service >/dev/null 2>&1; then
    service ssh restart 2>/dev/null || service sshd restart 2>/dev/null
    elif [ -x /etc/init.d/ssh ]; then
    /etc/init.d/ssh restart
    else
    echo "[!] Unable to automatically restart SSH. Please restart it manually."
    fi

    echo "[✓] SSH restart complete."
    echo "------------------------------------------------"
    echo "All SSH keys removed and configuration secured."
    echo "Backup of old config: $BACKUP_DIR"
}

function permissionAudit {
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
}

function patchPrivEsc {
    #Patches pwnkit, 
    chmod 0755 /usr/bin/pkexec


    #patches CVE-2023-32233
    sysctl -w kernel.unprivileged_userns_clone=0
    echo "kernel.unprivileged_userns_clone = 0" >> /etc/sysctl.conf
    sysctl -p
}

function searchSsn {
    print_banner "Searching for SSN Patterns"

    local rootdir="/home/"
    local ssn_pattern='[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}'

    log_info "Scanning $rootdir for files containing SSN patterns..."
    local found_match=0

    # Iterate over files ending in .txt or .csv under the rootdir
    while IFS= read -r file; do
        if grep -Eq "$ssn_pattern" "$file"; then
            log_warning "SSN pattern found in file: $file"
            grep -EHn "$ssn_pattern" "$file"
            found_match=1
            # Pause to let the user review the match before continuing.
            read -p "Press ENTER to continue scanning..."
        fi
    done < <(find "$rootdir" -type f \( -iname "*.txt" -o -iname "*.csv" \) 2>/dev/null)

    if [ $found_match -eq 0 ]; then
        log_info "No SSN patterns found in $rootdir."
    else
        log_info "Finished scanning. Please review the above matches."
    fi
}

function removeUnusedPackages {
    print_banner "Removing Unused Packages"

    if command -v yum >/dev/null; then
        sudo yum purge -y -q netcat nc gcc cmake make telnet
    elif command -v apt-get >/dev/null; then
        sudo apt-get -y purge netcat nc gcc cmake make telnet
    elif command -v apk >/dev/null; then
        sudo apk remove gcc make
    else
        echo "Unsupported package manager for package removal"
    fi
}

function hardenSysctl {
    file="/etc/sysctl.conf"
    echo "net.ipv4.tcp_syncookies = 1" >> $file
    echo "net.ipv4.tcp_synack_retries = 2" >> $file
    echo "net.ipv4.tcp_challenge_ack_limit = 1000000" >> $file
    echo "net.ipv4.tcp_rfc1337 = 1" >> $file
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> $file
    echo "net.ipv4.conf.all.accept_redirects = 0" >> $file
    echo "net.ipv4.icmp_echo_ignore_all = 1" >> $file
    echo "kernel.core_uses_pid = 1" >> $file
    echo "kernel.kptr_restrict = 2" >> $file
    echo "kernel.perf_event_paranoid = 2" >> $file
    echo "kernel.randomize_va_space = 2" >> $file
    echo "kernel.sysrq = 0" >> $file
    echo "kernel.yama.ptrace_scope = 2" >> $file
    echo "fs.protected_hardlinks = 1" >> $file
    echo "fs.protected_symlinks = 1" >> $file
    echo "fs.suid_dumpable = 0" >> $file
    echo "kernel.unprivileged_userns_clone = 0" >> $file
    echo "fs.protected_fifos = 2" >> $file
    echo "fs.protected_regular = 2" >> $file
    echo "kernel.kptr_restrict = 2" >> $file

    sysctl -p >/dev/null
}

function checkPackageIntegrity {
    print_banner "Verifying Package Integrity"

    if command -v debsums >/dev/null 2>&1; then
        echo "[+] Detected Debian/Ubuntu system"
        echo "[+] Running debsums to verify installed package checksums..."
        sudo apt install -y debsums >/dev/null 2>&1
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
        return 1
    fi

    echo "------------------------------------"
    echo "[✓] Package integrity verification completed."
}

function updatePackages {
    print_banner "Updating System Packages"

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
}


# cronControl usage: cronControl [--clear] [--revert]
function cronControl { 
    # Check all user crontabs
    for user in $(cut -f1 -d: /etc/passwd); do 
        crontab -u $user -l 2>/dev/null
    done

    # Check system cron
    cat /etc/crontab
    ls -la /etc/cron.*
    sys=$(command -v service || command -v systemctl || command -v rc-service)

    CHECKERR() {
        if [ ! $? -eq 0 ]; then
            echo "ERROR"
            exit 1
        else
            echo Success
        fi
    }

    # Default options
    CLEAR=0
    REVERT=0

    # Parse command-line arguments
    for arg in "$@"; do
        case $arg in
            --clear)
                CLEAR=1
                ;;
            --revert)
                REVERT=1
                ;;
            *)
                echo "Unknown option: $arg"
                exit 1
                ;;
        esac
    done

    # Clear cron jobs if requested
    if [ "$CLEAR" -eq 1 ]; then
        echo "Clearing all user cron jobs..."
        crontab -r
        CHECKERR
        if [ -f /etc/crontab ]; then
            echo > /etc/crontab
            CHECKERR
        fi
        echo "All cron jobs cleared."
        exit 0
    fi

    # Start or stop cron based on --revert
    if [ "$REVERT" -eq 1 ]; then
        if [ -f "/etc/rc.d/cron" ]; then
            /etc/rc.d/cron restart
            CHECKERR
        else
            $sys cron start || $sys restart cron || $sys crond start || $sys restart crond 
            CHECKERR
        fi
        echo "cron started"
    else
        if [ -f "/etc/rc.d/cron" ]; then
            /etc/rc.d/cron stop
            CHECKERR
        else
            $sys cron stop || $sys stop cron || $sys crond stop || $sys stop crond
            CHECKERR
        fi
        echo "cron stopped"
    fi
}

function lockAccounts {
    print_banner "Locking All Accounts Except Current User"

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
}

function auditStartupTasks {
    print_banner "Auditing Startup Tasks"
    
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
}

function auditServices {
    print_banner "Auditing System Services"
    
    HOSTNAME=$(hostname)
    echo "Host: $HOSTNAME"
    echo "----------------------------------------"
    
    # Output file for report
    REPORT="/tmp/service_audit_$(date +%F_%H-%M-%S).txt"
    echo "Service Audit Report - $(date)" > "$REPORT"
    echo "========================================" >> "$REPORT"
    
    # 1. List all running services
    echo -e "\n[+] Currently Running Services:"
    systemctl list-units --type=service --state=running --no-pager | tee -a "$REPORT"
    
    # 2. List all enabled services (will start on boot)
    echo -e "\n[+] Services Enabled at Boot:"
    systemctl list-unit-files --type=service --state=enabled --no-pager | tee -a "$REPORT"
    
    # 3. Check for suspicious/unnecessary services
    echo -e "\n[+] Checking for Potentially Unnecessary Services..."
    
    # Common unnecessary/risky services in competition environments
    suspicious_services=(
        "telnet"
        "rsh"
        "rlogin"
        "vsftpd"
        "ftpd"
        "apache2"
        "httpd"
        "nginx"
        "mysql"
        "mariadb"
        "postgresql"
        "samba"
        "smbd"
        "nmbd"
        "nfs-server"
        "rpcbind"
        "snmpd"
        "tftpd"
        "xinetd"
        "cups"
        "avahi-daemon"
        "bluetooth"
        "docker"
        "postfix"
        "dovecot"
        "bind9"
        "named"
        "squid"
    )
    
    found_suspicious=0
    for service in "${suspicious_services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo "  [!] RUNNING: $service" | tee -a "$REPORT"
            found_suspicious=1
        elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
            echo "  [!] ENABLED: $service (not currently running)" | tee -a "$REPORT"
            found_suspicious=1
        fi
    done
    
    if [ $found_suspicious -eq 0 ]; then
        echo "  [✓] No suspicious services detected" | tee -a "$REPORT"
    fi
    
    # 4. Check what's listening on network ports
    echo -e "\n[+] Services Listening on Network Ports:"
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn | grep LISTEN | tee -a "$REPORT"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulpn | grep LISTEN | tee -a "$REPORT"
    else
        echo "  [!] Neither 'ss' nor 'netstat' available" | tee -a "$REPORT"
    fi
    
    # 5. Check for failed services
    echo -e "\n[+] Failed Services:"
    systemctl list-units --type=service --state=failed --no-pager | tee -a "$REPORT"
    
    echo -e "\n----------------------------------------"
    echo "[✓] Service audit complete. Report saved to: $REPORT"
    
    # Optional: Interactive service management
    read -p "Do you want to interactively disable suspicious services? [y/N] " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        manageServices
    fi
}

function runAll {
    checkPermissions
    bulkDisableServices
    hardenIPtables
    setupSELinux
    setupAppArmor
    sudoCheck
    groupMemberships
    rotatePasswords
    sshConfig
    permissionAudit
    patchPrivEsc
    searchSsn
    removeUnusedPackages
    hardenSysctl
    checkPackageIntegrity
    updatePackages
    cronControl
    lockAccounts
    auditStartupTasks
    auditServices
}

runAll
