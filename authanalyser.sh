#!/bin/bash

# -----------------------------
# SSH Authentication Log Analyzer
# -----------------------------
# Purpose:
# Analyze failed SSH login attempts
# and identify suspicious IP addresses
# -----------------------------

#LOG_FILE="/var/log/auth.log"  #saving authlog file to a variable

LOG_FILE=${1:-/var/log/auth.log}
#aboove line accepts any file with executable command like ./authanalyzer.sh sampleauth.log if not given any file takes authlog as default
THRESHOLD=3   #if a similar IP address comes 3 times mark it as suspicious

echo "Analyzing failed SSH login attempts..."
echo "-------------------------------------"

# Check if log file exists
if [ ! -f "$LOG_FILE" ]; then     #prevents script failure if log doesnt exists
    echo "Log file not found: $LOG_FILE"
    exit 1
fi

read -p "Enter Start date (eg Jan 14): " start_date
read -p "Enter End date (eg Jan 16 ): " end_date

#validate input
if [ -z "$start_date" ] || [ -z "$end_date" ]; then
   echo "Data range not provided. Exiting"
    exit 1
fi

# Extract failed SSH attempts, get IPs, count occurrences
RESULT=$(awk "
\$0 ~ \"$start_date\" {flag=1}
flag && \$0 ~ /sshd.*Failed password/ {
        for (i=1; i<=NF; i++)
            if (\$i == \"from\") print \$(i+1)
}
\$0 ~ \"$end_date\" {exit}
" "$LOG_FILE" | \
sort | \
uniq -c | \
sort -nr)

#if nothing is found
if [ -z "$RESULT" ]; then
    echo "No failed SSH login attempts found."
    echo "System looks safe 👍"
    exit 0
fi

echo "$RESULT" | awk -v limit="$THRESHOLD" '
BEGIN { alert=0 }

{
    if ($1 >= limit) {
        print "ALERT: Suspicious IP ->", $2, "Attempts:", $1
        alert=1
    }
}
END {
    if (alert==0)
        print "No IP crossed the alert threshold."
}
'
echo "-------------------------------------"
echo "Analysis complete."
