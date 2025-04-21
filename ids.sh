#!/bin/bash

while true; do
sleep 30

ALERT_LOG="alerts.log"
ARCHIVE_LOG="alerts_archives.log"
EMAIL="faisalbeach25@hotmail.com"

./fim.sh
./DoS_detect.sh
./logMonitoring.sh

if [[ -s "$ALERT_LOG" ]]; then # checks if alerts.log exists and has content
    # Append current alerts to the archive log before clearing
    cat "$ALERT_LOG" >> "$ARCHIVE_LOG"

    # Send an email with the alert log as the message body
    mail -s "Security Alert" "$EMAIL" < "$ALERT_LOG"

    # Now clear the log to prevent duplicate emails
    > "$ALERT_LOG"

    echo "$(date): Alerts emailed and archived." >> "$ARCHIVE_LOG"
fi
done
