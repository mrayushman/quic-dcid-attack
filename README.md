# QUIC DCID Rotation Attack and Mitigation on 5G UPF

## Components

| File | Machine | Role |
|---|---|---|
| `dos_client_dcid.py` | Client | QUIC attack client |
| `ultimate_attack_dcid.sh` | Client | Runs 150 rounds across 150 IPs |
| `endpoint.c` | Client | XDP+kprobe eBPF — detects DCID changes |
| `endpoint.py` | Client | Reads eBPF maps every 1ms, sends to client_agent |
| `client_agent.py` | Client | Forwards DCID→O-DCID to Tracking Agent |
| `dos_server.py` | Server | QUIC server on port 4444 |
| `agent.py` | TA (172.16.0.113) | Stores mappings, pushes to UPF |
| `quic_conn_table_dcid.c` | UPF | XDP — extracts DCID from packets |
| `quic_aware_nat_dcid.py` | UPF | Two-table QUIC-aware tracking |

---

## Packet Flow

```
dos_client_dcid.py
  → change_connection_id()   # new DCID from server
  → change_transport()       # new UDP socket, new src_port
  → sends packet to 172.16.20.123:4444 via UPF
```

---

## Control Signal Flow

```
[CLIENT MACHINE]

endpoint.c (XDP + kprobe on ens18)
  → sees new 5-tuple packet
  → resolves DCID → O-DCID via dcids_map + sip_map
  → stores in connections_map with first_dcid = O-DCID

endpoint.py (polls connections_map every 1ms)
  → finds entries where dcid != first_dcid
  → sends Configuration(original_cid, peer_cid) to 127.0.0.1:9999

client_agent.py (listens on port 9999)
  → receives Configuration from endpoint.py
  → forwards to Tracking Agent at 172.16.0.113:12000

[TRACKING AGENT — 172.16.0.113]

agent.py (listens on port 12000)
  → deserialises Configuration
  → stores peer_cid → original_cid in mapping dict
  → pushes {"dcid": X, "gcid": O-DCID} to UPF:13000

[UPF — 172.16.0.5]

quic_conn_table_dcid.c (XDP on enp6s18)
  → extracts DCID from every QUIC packet to port 4444
  → submits pkt_event to perf buffer

quic_aware_nat_dcid.py
  push_listener thread (port 13000):
    → receives push from agent
    → updates T1[dcid] = gcid
    → merges T2: moves T2[dcid] entry to T2[gcid]

  main loop (perf_buffer_poll):
    → reads pkt_event from XDP
    → get_gcid(dcid): checks T1, miss queries TA:12001
    → quic_set(src_ip, src_port, gcid):
        new GCID            → INSERT  (new connection)
        same GCID, diff src → UPDATE  (migration)
        same GCID, same src → LOOKUP  (same path)
```

---

## Running Order

```bash
# 1. Tracking Agent (172.16.0.113)
cd ~/quic-aware-middlebox/online && python3 agent.py &

# 2. Server (172.16.20.123)
python3 dos_server.py -c cert.pem -k key.pem --host 172.16.20.123 --port 4444

# 3. UPF (172.16.0.5)
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout=900
sudo python3 quic_aware_nat_dcid.py

# 4. Client (172.16.0.124)
sudo ip route add 172.16.20.0/24 via 172.16.0.5 dev ens18
python3 client_agent.py &
sudo python3 endpoint.py &
bash ultimate_attack_dcid.sh
```

---

## Results

| Metric | Value |
|---|---|
| Peak Linux conntrack | 100,000 (DoS!) |
| Table 2 (our solution) | ~3,000 entries |
| Reduction | ~33x fewer |
| Push latency | 7–35ms |
