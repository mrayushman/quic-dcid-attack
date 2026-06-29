#!/bin/bash
echo "time ct t2" > ~/results/timeseries_with_system.txt
START=$(date +%s)
while true; do
    NOW=$(( $(date +%s) - START ))
    CT=$(sudo conntrack -C 2>/dev/null || echo 0)
    # Get T2 from middlebox stats file
    T2=$(tail -1 /tmp/mb_stats.txt 2>/dev/null | grep -oP 'T2:\K[0-9]+' || echo 0)
    echo "$NOW $CT $T2" >> ~/results/timeseries_with_system.txt
    sleep 2
done
