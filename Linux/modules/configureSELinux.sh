#!/bin/bash
# modules/selinuxSetup.sh - SELinux Configuration and Hardening

set -euo pipefail

echo "=== SELinux Setup and Configuration ==="
HOSTNAME=$(hostname)
echo "Host: $HOSTNAME"
echo "----------------------------------------"

# ============================================
# Configuration Variables
# ============================================
SELINUX_CONFIG="/etc/selinux/config"
SELINUX_BACKUP="/etc/selinux/config.backup.$(date +%F_%H-%M-%S)"

# Target mode (enforcing, permissive, disabled)
TARGET_MODE="enforcing"

# ============================================
# Check Current SELinux Status
# ============================================

echo "[+] Checking SELinux status..."

if ! command -v getenforce >/dev/null 2>&1; then
    echo "[!] SELinux tools not found"
    
    # Check if this is a system that supports SELinux
    if [[ -f /etc/redhat-release ]] || [[ -f /etc/fedora-release ]] || [[ -f /etc/centos-release ]]; then
        echo "[!] This appears to be a RHEL-based system"
        read -p "Install SELinux? (Y/n): " install_choice
        
        if [[ ! "$install_choice" =~ ^[Nn]$ ]]; then
            echo "[+] Installing SELinux packages..."
            
            if command -v dnf >/dev/null 2>&1; then
                sudo dnf install -y selinux-policy selinux-policy-targeted \
                    policycoreutils policycoreutils-python-utils \
                    setools-console setroubleshoot-server
            elif command -v yum >/dev/null 2>&1; then
                sudo yum install -y selinux-policy selinux-policy-targeted \
                    policycoreutils policycoreutils-python \
                    setools-console setroubleshoot-server
            fi
            
            echo "    [✓] SELinux packages installed"
        else
            echo "[!] Skipping SELinux setup"
            exit 0
        fi
    else
        echo "[!] SELinux is primarily for RHEL-based systems"
        echo "[!] This system uses AppArmor or another MAC system"
        echo "[!] Skipping SELinux setup"
        exit 0
    fi
else
    CURRENT_STATUS=$(getenforce)
    echo "    Current Status: $CURRENT_STATUS"
fi

# ============================================
# Interactive Configuration
# ============================================

echo ""
echo "[?] SELinux Configuration"
echo "    1) enforcing  - Full protection (recommended for production)"
echo "    2) permissive - Logs violations but doesn't block (good for testing)"
echo "    3) disabled   - SELinux turned off (NOT recommended)"
echo ""

read -p "Select mode [1-3] (default: 1): " mode_choice

case "${mode_choice:-1}" in
    1) TARGET_MODE="enforcing" ;;
    2) TARGET_MODE="permissive" ;;
    3) 
        read -p "WARNING: Disabling SELinux reduces security. Are you sure? (yes/NO): " confirm
        if [[ "$confirm" == "yes" ]]; then
            TARGET_MODE="disabled"
        else
            echo "Keeping current mode"
            exit 0
        fi
        ;;
    *) 
        echo "Invalid choice, using enforcing mode"
        TARGET_MODE="enforcing"
        ;;
esac

echo "[+] Target mode: $TARGET_MODE"

# ============================================
# Backup Configuration
# ============================================

if [[ -f "$SELINUX_CONFIG" ]]; then
    echo "[+] Backing up SELinux configuration..."
    sudo cp "$SELINUX_CONFIG" "$SELINUX_BACKUP"
    echo "    [✓] Backup saved to: $SELINUX_BACKUP"
fi

# ============================================
# Configure SELinux
# ============================================

echo "[+] Configuring SELinux..."

# Update configuration file
if [[ -f "$SELINUX_CONFIG" ]]; then
    sudo sed -i "s/^SELINUX=.*/SELINUX=$TARGET_MODE/" "$SELINUX_CONFIG"
    sudo sed -i "s/^SELINUXTYPE=.*/SELINUXTYPE=targeted/" "$SELINUX_CONFIG"
    echo "    [✓] Configuration file updated"
else
    # Create configuration file if it doesn't exist
    sudo mkdir -p /etc/selinux
    sudo tee "$SELINUX_CONFIG" >/dev/null <<EOF
# SELinux configuration
# Generated: $(date)

SELINUX=$TARGET_MODE
SELINUXTYPE=targeted
EOF
    echo "    [✓] Configuration file created"
fi

# Set current mode if possible (without reboot)
CURRENT_MODE=$(getenforce 2>/dev/null || echo "unknown")

if [[ "$CURRENT_MODE" == "Disabled" ]] && [[ "$TARGET_MODE" != "disabled" ]]; then
    echo ""
    echo "[!] SELinux is currently disabled"
    echo "[!] Enabling SELinux requires:"
    echo "    1. System reboot"
    echo "    2. Full filesystem relabel (may take time)"
    echo ""
    read -p "Reboot now to enable SELinux? (y/N): " reboot_choice
    
    if [[ "$reboot_choice" =~ ^[Yy]$ ]]; then
        echo "[!] System will reboot in 10 seconds..."
        echo "[!] After reboot, SELinux will relabel the filesystem"
        sudo touch /.autorelabel
        sleep 10
        sudo reboot
    else
        echo "[!] SELinux will be enabled on next reboot"
        echo "[!] Run: sudo touch /.autorelabel && sudo reboot"
    fi
elif [[ "$CURRENT_MODE" != "Disabled" ]]; then
    # Can change between enforcing/permissive without reboot
    if [[ "$TARGET_MODE" == "enforcing" ]]; then
        sudo setenforce 1 2>/dev/null || true
        echo "    [✓] SELinux set to enforcing mode"
    elif [[ "$TARGET_MODE" == "permissive" ]]; then
        sudo setenforce 0 2>/dev/null || true
        echo "    [✓] SELinux set to permissive mode"
    elif [[ "$TARGET_MODE" == "disabled" ]]; then
        echo "    [!] SELinux will be disabled on next reboot"
    fi
fi

# ============================================
# Configure SELinux Booleans (Common Settings)
# ============================================

if [[ "$TARGET_MODE" != "disabled" ]] && command -v getsebool >/dev/null 2>&1; then
    echo ""
    echo "[+] Configuring SELinux booleans..."
    
    # Define booleans with recommended settings
    declare -A BOOLEANS=(
        # Web Server
        ["httpd_can_network_connect"]="off"           # Apache can't make network connections
        ["httpd_can_network_connect_db"]="on"         # Apache can connect to databases
        ["httpd_can_sendmail"]="off"                  # Apache can't send email
        ["httpd_enable_homedirs"]="off"               # Apache can't access user home dirs
        ["httpd_execmem"]="off"                       # Prevents memory execution attacks
        
        # FTP
        ["ftpd_full_access"]="off"                    # FTP has restricted access
        ["ftpd_anon_write"]="off"                     # Anonymous FTP can't write
        
        # NFS (disable if not needed)
        ["nfs_export_all_rw"]="off"                   # NFS can't export everything
        ["nfs_export_all_ro"]="off"                   # NFS can't export everything read-only
        
        # Samba
        ["samba_enable_home_dirs"]="off"              # Samba can't access home dirs
        ["samba_export_all_rw"]="off"                 # Samba can't export everything
        
        # User permissions
        ["user_exec_content"]="on"                    # Users can execute files in home dir
        
        # SSH
        ["ssh_chroot_rw_homedirs"]="off"              # SSH chroot users can't write to home
        
        # System
        ["allow_execheap"]="off"                      # Prevent heap execution
        ["allow_execmem"]="off"                       # Prevent memory execution
        ["allow_execstack"]="off"                     # Prevent stack execution
    )
    
    for bool in "${!BOOLEANS[@]}"; do
        if sudo getsebool "$bool" >/dev/null 2>&1; then
            current_value=$(sudo getsebool "$bool" | awk '{print $3}')
            target_value="${BOOLEANS[$bool]}"
            
            if [[ "$current_value" != "$target_value" ]]; then
                sudo setsebool -P "$bool" "$target_value" 2>/dev/null && \
                    echo "    [✓] $bool: $current_value -> $target_value" || \
                    echo "    [!] Failed to set $bool"
            fi
        fi
    done
    
    echo "    [✓] Boolean configuration complete"
fi

# ============================================
# Port Labeling for Custom Services
# ============================================

if [[ "$TARGET_MODE" != "disabled" ]] && command -v semanage >/dev/null 2>&1; then
    echo ""
    echo "[+] Checking port labels..."
    
    # Example: Allow SSH on custom port
    read -p "Is SSH running on a non-standard port? (y/N): " custom_ssh
    if [[ "$custom_ssh" =~ ^[Yy]$ ]]; then
        read -p "Enter SSH port number: " ssh_port
        if [[ -n "$ssh_port" ]] && [[ "$ssh_port" -ne 22 ]]; then
            sudo semanage port -a -t ssh_port_t -p tcp "$ssh_port" 2>/dev/null || \
                sudo semanage port -m -t ssh_port_t -p tcp "$ssh_port"
            echo "    [✓] SSH port $ssh_port labeled"
        fi
    fi
    
    # Example: Allow HTTP on custom port
    read -p "Is web server running on a non-standard port? (y/N): " custom_http
    if [[ "$custom_http" =~ ^[Yy]$ ]]; then
        read -p "Enter HTTP port number: " http_port
        if [[ -n "$http_port" ]] && [[ "$http_port" -ne 80 ]] && [[ "$http_port" -ne 443 ]]; then
            sudo semanage port -a -t http_port_t -p tcp "$http_port" 2>/dev/null || \
                sudo semanage port -m -t http_port_t -p tcp "$http_port"
            echo "    [✓] HTTP port $http_port labeled"
        fi
    fi
fi

# ============================================
# File Context Management
# ============================================

if [[ "$TARGET_MODE" != "disabled" ]] && command -v restorecon >/dev/null 2>&1; then
    echo ""
    echo "[+] Restoring file contexts for common directories..."
    
    # Common directories that might need context restoration
    DIRS_TO_RESTORE=(
        "/var/www"
        "/etc/httpd"
        "/etc/nginx"
        "/home"
        "/var/log"
    )
    
    for dir in "${DIRS_TO_RESTORE[@]}"; do
        if [[ -d "$dir" ]]; then
            sudo restorecon -R "$dir" 2>/dev/null && \
                echo "    [✓] Restored context: $dir" || \
                echo "    [!] Could not restore: $dir"
        fi
    done
fi

# ============================================
# Troubleshooting Mode
# ============================================

if [[ "$TARGET_MODE" == "permissive" ]]; then
    echo ""
    echo "[+] Setting up troubleshooting tools..."
    
    # Install audit2allow if not present
    if ! command -v audit2allow >/dev/null 2>&1; then
        echo "    [+] Installing audit2allow..."
        if command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y policycoreutils-python-utils
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y policycoreutils-python
        fi
    fi
    
    echo ""
    echo "[!] SELinux is in PERMISSIVE mode for troubleshooting"
    echo "[!] This will log violations without blocking them"
    echo ""
    echo "To view denials:"
    echo "  • ausearch -m AVC -ts recent"
    echo "  • grep AVC /var/log/audit/audit.log"
    echo ""
    echo "To create policy from denials:"
    echo "  • audit2allow -a"
    echo "  • audit2allow -a -M mypolicy"
    echo "  • semodule -i mypolicy.pp"
fi

# ============================================
# Create Management Script
# ============================================

echo ""
echo "[+] Creating SELinux management script..."

sudo tee /usr/local/bin/selinux-manage >/dev/null <<'EOFSCRIPT'
#!/bin/bash
# SELinux Management Script

case "$1" in
    status)
        echo "=== SELinux Status ==="
        echo "Current mode: $(getenforce)"
        echo "Config mode: $(grep ^SELINUX= /etc/selinux/config | cut -d= -f2)"
        sestatus
        ;;
    enforcing)
        echo "Setting SELinux to enforcing mode..."
        setenforce 1
        sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
        echo "Done"
        ;;
    permissive)
        echo "Setting SELinux to permissive mode..."
        setenforce 0
        sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
        echo "Done"
        ;;
    denials)
        echo "=== Recent SELinux Denials ==="
        ausearch -m AVC -ts recent 2>/dev/null || grep AVC /var/log/audit/audit.log | tail -20
        ;;
    fix)
        if [[ -z "$2" ]]; then
            echo "Generating policy for all recent denials..."
            audit2allow -a -M autopolicy
            semodule -i autopolicy.pp
            rm -f autopolicy.pp autopolicy.te
            echo "Policy installed. Monitor for additional denials."
        else
            restorecon -Rv "$2"
        fi
        ;;
    ports)
        echo "=== Custom Port Labels ==="
        semanage port -l | grep -v "^$" | head -50
        ;;
    booleans)
        echo "=== SELinux Booleans (non-default) ==="
        getsebool -a | grep " --> on"
        ;;
    contexts)
        if [[ -z "$2" ]]; then
            echo "Usage: $0 contexts <path>"
            exit 1
        fi
        ls -lZ "$2"
        ;;
    relabel)
        echo "Scheduling full filesystem relabel on next boot..."
        touch /.autorelabel
        echo "Done. Reboot to apply."
        ;;
    *)
        echo "SELinux Management Script"
        echo ""
        echo "Usage: $0 {status|enforcing|permissive|denials|fix|ports|booleans|contexts|relabel}"
        echo ""
        echo "Commands:"
        echo "  status            - Show SELinux status"
        echo "  enforcing         - Set to enforcing mode"
        echo "  permissive        - Set to permissive mode"
        echo "  denials           - Show recent denials"
        echo "  fix [path]        - Generate policy from denials or restore context"
        echo "  ports             - List custom port labels"
        echo "  booleans          - List active booleans"
        echo "  contexts <path>   - Show SELinux contexts for path"
        echo "  relabel           - Schedule filesystem relabel on reboot"
        exit 1
        ;;
esac
EOFSCRIPT

sudo chmod +x /usr/local/bin/selinux-manage
echo "    [✓] Management script created: /usr/local/bin/selinux-manage"

# ============================================
# Generate Report
# ============================================

REPORT="/tmp/selinux_setup_$(date +%F_%H-%M-%S).txt"
cat > "$REPORT" <<EOF
SELinux Setup Report
====================
Date: $(date)
Hostname: $HOSTNAME

Configuration:
--------------
Target Mode: $TARGET_MODE
Config File: $SELINUX_CONFIG
Backup: $SELINUX_BACKUP

Current Status:
---------------
$(sestatus 2>/dev/null || echo "SELinux not fully initialized")

Management Commands:
--------------------
Status:        selinux-manage status
Set Enforcing: selinux-manage enforcing
Set Permissive:selinux-manage permissive
View Denials:  selinux-manage denials
Fix Issues:    selinux-manage fix
List Ports:    selinux-manage ports
Show Contexts: selinux-manage contexts <path>
Relabel FS:    selinux-manage relabel

Troubleshooting:
----------------
View denials:   ausearch -m AVC -ts recent
Create policy:  audit2allow -a -M mypolicy && semodule -i mypolicy.pp
Restore context:restorecon -Rv <path>
Check context:  ls -lZ <path>
Change context: chcon -t <type> <path>
Add port label: semanage port -a -t <type> -p tcp <port>

Important Notes:
----------------
EOF

if [[ "$TARGET_MODE" != "disabled" ]] && [[ "$CURRENT_MODE" == "Disabled" ]]; then
    cat >> "$REPORT" <<EOF
[!] SELinux will be enabled on next reboot
[!] Filesystem relabel will occur automatically
[!] First boot after enabling may take extra time

EOF
fi

cat >> "$REPORT" <<EOF
Documentation: /usr/share/doc/selinux-policy/
Log File: /var/log/audit/audit.log
EOF

echo ""
echo "===================================="
echo "[✓] SELinux Setup Complete!"
echo "===================================="
echo ""
echo "Report saved to: $REPORT"
echo ""
echo "Current Status: $(getenforce 2>/dev/null || echo 'Needs reboot')"
echo "Target Mode: $TARGET_MODE"
echo ""
echo "Quick Commands:"
echo "  • Check status:  selinux-manage status"
echo "  • View denials:  selinux-manage denials"
echo "  • Fix issues:    selinux-manage fix"
echo ""

if [[ "$TARGET_MODE" != "disabled" ]] && [[ "$CURRENT_MODE" == "Disabled" ]]; then
    echo "[!] Reboot required to enable SELinux"
    echo "[!] Run: sudo touch /.autorelabel && sudo reboot"
fi

echo "----------------------------------------"