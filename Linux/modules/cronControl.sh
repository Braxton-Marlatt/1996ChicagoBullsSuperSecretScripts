#!/bin/bash
# WARNING: This script will clear ALL cron jobs on this system:
# - all user crontabs
# - the system crontab (/etc/crontab)
# - files in /etc/cron.d, /etc/cron.{hourly,daily,weekly,monthly}
# Run as root.

echo "Clearing all user crontabs..."
while IFS=: read -r user _; do
    crontab -r -u "$user" 2>/dev/null || true
done < /etc/passwd

echo "Clearing system crontab (/etc/crontab)..."
if [ -f /etc/crontab ]; then
    : > /etc/crontab 2>/dev/null || echo "Could not truncate /etc/crontab"
fi

echo "Clearing cron.d and periodic cron directories..."
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$d" ]; then
        # Remove all regular files (leave directory + special files alone)
        find "$d" -type f -exec rm -f {} + 2>/dev/null
    fi
done

echo "All cron jobs cleared."
