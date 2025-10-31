  #!/bin/bash
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