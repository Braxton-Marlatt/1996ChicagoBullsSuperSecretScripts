#!/bin/bash
# cronControl usage: cronControl [--clear] [--revert]

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