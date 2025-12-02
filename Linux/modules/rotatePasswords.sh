#!/bin/bash

##############################################################################
# Password Rotation Script
# Purpose: Iterate through system users and prompt for password changes
# Usage: sudo ./rotatePasswords.sh
##############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

log "Starting password rotation process"
log "=================================="

# Get list of all users with valid shells (excluding system users)
# This filters for users with UID >= 1000 and shell != nologin/false
users=$(awk -F: '($3 >= 1000 || $1 == "root") && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1}' /etc/passwd)

if [[ -z "$users" ]]; then
    error "No users found to process"
    exit 1
fi

user_count=$(echo "$users" | wc -l)
log "Found $user_count user(s) to process"
echo ""

# Counter for tracking progress
current=1

for user in $users; do
    echo -e "${YELLOW}[User $current/$user_count]${NC} Processing user: ${GREEN}$user${NC}"

    # Check if user exists
    if ! id "$user" &>/dev/null; then
        warn "User '$user' not found, skipping"
        ((current++))
        continue
    fi

    # Prompt to change password
    read -p "Do you want to change password for '$user'? (y/n): " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Changing password for $user..."
        if passwd "$user"; then
            log "Password changed successfully for $user"
        else
            error "Failed to change password for $user"
        fi
    else
        log "Skipped password change for $user"
    fi

    echo ""
    ((current++))
done

log "Password rotation process completed"
log "===================================="
