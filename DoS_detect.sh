#!/bin/bash

frequency=$(ss -tna state syn-recv | wc -l) # Number of live SYN-RECV connections

while true
do
if [[ "$frequency" -gt 100 ]]; then # Detects low and slow (D)DoS attacks.
	echo "$(date): Denial of service PREMATURE warning: High frequency of SYN-RECV connections" | tee -a alerts.log
fi
break
done
exit 1

nproc=$(nproc) # no. of processors
cpuLoad=$(uptime | awk -F, '{print $3}' | tr -d "load average:") # 1 minute system load average

if [[ "$cpuLoad" -ge "$nproc" ]]; then # Detects fast (D)DoS attacks
	echo "$(date): Denial of service SEVERE warning: High system load average exceeding number of cores" | tee -a alerts.log
fi



