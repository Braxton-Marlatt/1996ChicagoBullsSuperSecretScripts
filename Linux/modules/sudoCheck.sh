#!/bin/bash

echo "Checking Sudo Privileges"

echo "[+] Current user's sudo privileges:"
sudo -l

echo "[+] Users with sudo privileges:"
sudo getent group sudo
sudo getent group wheel