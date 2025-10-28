#!/usr/bin/env bash

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
    iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
    
    # Block everything by default
    iptables -t filter -P INPUT DROP
    iptables -t filter -P FORWARD DROP
    iptables -t filter -P OUTPUT DROP
    
    # Allow loopback communications
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
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

function runAll {
    checkPermissions
    bulkDisableServices
    hardenIPtables
    setupSELinux
}

runAll
