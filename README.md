# QUIC DCID Rotation Attack and Mitigation on 5G UPF
## Components
FileMachineRoledos_client_dcid.pyClientQUIC attack clientultimate_attack_dcid.shClientRuns 150 rounds across 150 IPsendpoint.cClientXDP+kprobe eBPF detects DCID changesendpoint.pyClientReads eBPF maps every 1ms, sends to client_agentclient_agent.pyClientForwards DCID to O-DCID to Tracking Agentdos_server.pyServerQUIC server on port 4444agent.pyTA 172.16.0.113Stores mappings, pushes to UPFquic_conn_table_dcid.cUPFXDP extracts DCID from packetsquic_aware_nat_dcid.pyUPFTwo-table QUIC-aware tracking
## Packet Flow
dos_client_dcid.py calls change_connection_id() to get a new DCID from the server, then calls change_transport() to open a new UDP socket with a new src_port, then sends the packet to 172.16.20.123:4444 through the UPF.
## Control Signal Flow
CLIENT MACHINE
endpoint.c runs as XDP and kprobe on interface ens18. It sees every new 5-tuple packet, resolves the DCID to its O-DCID using dcids_map and sip_map, and stores the result in connections_map with first_dcid set to the O-DCID.
endpoint.py polls connections_map every 1ms. When it finds an entry where dcid is not equal to first_dcid, it sends a Configuration object containing original_cid and peer_cid to 127.0.0.1:9999.
client_agent.py listens on port 9999. It receives the Configuration from endpoint.py and forwards it to the Tracking Agent at 172.16.0.113:12000.
TRACKING AGENT 172.16.0.113
agent.py listens on port 12000. It deserialises the Configuration, stores peer_cid mapped to original_cid in its dictionary, and immediately pushes a JSON message with dcid and gcid fields to the UPF at 172.16.0.5:13000.
UPF 172.16.0.5
quic_conn_table_dcid.c runs as XDP on interface enp6s18. It extracts the DCID from every QUIC packet destined for port 4444 and submits a pkt_event to the perf buffer.
quic_aware_nat_dcid.py runs two threads. The push_listener thread binds to port 13000, receives pushes from the agent, updates T1 with dcid mapped to gcid, and merges any T2 entry wrongly keyed under dcid into the correct gcid key. The main loop calls perf_buffer_poll continuously, reads each pkt_event, calls get_gcid to look up T1 or query TA on port 12001, then calls quic_set which inserts a new T2 entry for a new connection, updates the existing T2 entry on migration, or increments the lookup counter for the same path.
## Running Order

Tracking Agent on 172.16.0.113

cd ~/quic-aware-middlebox/online && python3 agent.py &

Server on 172.16.20.123

python3 dos_server.py -c cert.pem -k key.pem --host 172.16.20.123 --port 4444

UPF on 172.16.0.5

sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout=900
sudo python3 quic_aware_nat_dcid.py

Client on 172.16.0.124

sudo ip route add 172.16.20.0/24 via 172.16.0.5 dev ens18
python3 client_agent.py &
sudo python3 endpoint.py &
bash ultimate_attack_dcid.sh


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
