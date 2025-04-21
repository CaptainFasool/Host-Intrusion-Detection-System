#!/bin/bash

# Detect failed authentication attempts in journalctl (systemd) logs
if sudo journalctl -b -u ssh | grep -q 'Failed password'; then
    echo "$(date): Failed SSH password authentication" | tee -a alerts.log
fi
if sudo journalctl -b | grep -q 'user NOT in sudoers'; then
    echo "$(date): Unauthorized sudo usage" | tee -a alerts.log
fi
if sudo journalctl -b | grep -q 'pam_unix(su:auth): authentication failure'; then
    echo "$(date): Failed su command password authentication" | tee -a alerts.log
fi

# Audit rules
declare -a AUDITD_RULES=(
"-a always,exit -F arch=b64 -S execve -F path=/bin/chmod -F perm=x -F key=chmod_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/useradd -F perm=x -F key=useradd_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/adduser -F perm=x -F key=adduser_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/passwd -F perm=x -F key=passwd_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/usermod -F perm=x -F key=usermod_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/groupadd -F perm=x -F key=groupadd_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/groupdel -F perm=x -F key=groupdel_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/systemctl -F perm=x -F key=systemctl_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/iptables -F perm=x -F key=iptables_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/ufw -F perm=x -F key=ufw_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/crontab -F perm=x -F key=crontab_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/nc -F perm=x -F key=nc_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/nmap -F perm=x -F key=nmap_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/tcpdump -F perm=x -F key=tcpdump_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/wireshark -F perm=x -F key=wireshark_exec"
"-a always,exit -F arch=b64 -S execve -F path=/bin/rm -F perm=x -F key=rm_exec"
)

# Apply each audit rule and check for events
for rule in "${AUDITD_RULES[@]}"; do
    # Extract key name from the rule
    key=$(echo "$rule" | grep -oP '(?<=key=)[^ ]+')

    # Check if rule already exists
    if sudo auditctl -l | grep -q "key=$key"; then
        : # do nothing
    else
        # Apply the rule by breaking it into arguments
        read -r -a rule_args <<< "$rule"
        sudo auditctl "${rule_args[@]}"
    fi

    # Now check for any suspicious activities with this audit rule key
    if [[ -n "$key" ]]; then
	# Extract non-admin UID (>= 1001) from auditd logs
        uid=$(sudo ausearch --start boot -k "$key" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /^uid=[0-9]+$/) {split($i, arr, "="); if (arr[2] >= 1001) print $0}}')
        if [[ -n "$uid" ]]; then # Fire alert if UID is greater than or equal to 1001 (non-admin user attempting to run powerful commands)
            echo "$(date): $key suspicious command execution from: $uid" | tee -a alerts.log
        fi
    fi
done
