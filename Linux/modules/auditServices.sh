#!/bin/bash
echo "Auditing System Services"

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
