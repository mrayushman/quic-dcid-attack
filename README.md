# Client Execution

The client-side attack environment requires multiple coordinated processes running in separate terminals.

## Terminal 1 — Cleanup and Client Agent

```bash
sudo lsof -ti:9999 | xargs -r sudo kill -9 && sleep 1

sudo truncate -s 0 ~/logs/client_agent_log.txt

sudo rm -f /tmp/qlog/*.qlog && mkdir -p /tmp/qlog

python3 ~/client_agent.py &
```

## Terminal 2 — Endpoint/DCID Controller

```bash
sudo python3 ~/endpoint_dcid.py &
```

## Terminal 3 — Route Configuration and Attack Launch

```bash
sudo ip route add 172.16.20.0/24 via 172.16.0.5 dev ens18 2>/dev/null

source ~/http3-vulnerability-analysis/quic-env/bin/activate

bash ~/ultimate_attack_dcid.sh
```

---

# Server Execution

## Terminal 1 — Start QUIC Server

```bash
pkill -f dos_server

python3 dos_server.py -c cert.pem -k key.pem --host 172.16.20.123 --port 4444
```

# UPF / NAT Execution

## Terminal 1 — Start QUIC-Aware NAT

```bash
sudo pkill -f quic_aware_nat && sudo conntrack -F

sudo sysctl -w net.ipv4.conf.all.send_redirects=0

sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout=900

sudo ip addr del 172.16.0.125/24 dev enp6s21 2>/dev/null

sudo python3 ~/quic_aware_nat_dcid.py
```



# Tracking Agent

## Terminal 1 — Start Tracking Agent

```bash
sudo pkill -9 python3 && sleep 2

cd ~/quic-aware-middlebox/online && python3 agent.py &
```

## Verify Tracking Agent

```bash
sleep 1 && curl http://localhost:12002/count
```

Expected output:

```text
0
```
