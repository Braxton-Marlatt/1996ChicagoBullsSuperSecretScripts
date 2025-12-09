#!/bin/bash

#Patches pwnkit
if [ -f /usr/bin/pkexec ]; then
    chmod 0755 /usr/bin/pkexec
fi


#patches CVE-2023-32233
if ! grep -q "kernel.unprivileged_userns_clone" /etc/sysctl.conf 2>/dev/null; then
    echo "kernel.unprivileged_userns_clone = 0" >> /etc/sysctl.conf
fi
sysctl -w kernel.unprivileged_userns_clone=0