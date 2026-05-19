#!/usr/bin/env python3
"""
QUIC-aware Connection Tracking
Implements paper's quic_set logic with two tables:
Table 1: DCID -> GCID cache (like quic_cids in paper)
Table 2: GCID -> connection state (like quic_lan_map in paper)
"""
from bcc import BPF
import ctypes
import socket
import subprocess
import time

# Config
INTERFACE   = "enp6s18"
SERVER_IP   = "172.16.20.123"
SERVER_PORT = 4444
TA_IP       = "172.16.0.113"
TA_PORT     = 12001

# XDP program - extracts DCID and signals userspace
XDP_PROG = """
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct pkt_event {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  dcid_len;
    __u8  dcid[20];
};

BPF_PERF_OUTPUT(pkt_events);

int track(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth+1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(0x0800)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth+1);
    if ((void *)(ip+1) > data_end) return XDP_PASS;
    if (ip->protocol != 17) return XDP_PASS;

    struct udphdr *udp = (void *)(ip+1);
    if ((void *)(udp+1) > data_end) return XDP_PASS;
    if (ntohs(udp->dest) != 4444) return XDP_PASS;

    __u8 *payload = (void *)(udp+1);
    if ((void *)(payload + 27) > data_end) return XDP_PASS;

    struct pkt_event evt = {};
    evt.src_ip   = ntohl(ip->saddr);
    evt.src_port = ntohs(udp->source);
    evt.dst_ip   = ntohl(ip->daddr);
    evt.dst_port = ntohs(udp->dest);

    /* Long header */
    if ((payload[0] & 0x80) && (payload[0] & 0x40)) {
        if (payload[1]==0 && payload[2]==0 && payload[3]==0 && payload[4]==1) {
            __u8 dlen = payload[5];
            if (dlen > 0 && dlen <= 20) {
                evt.dcid_len = dlen;
                if ((void *)(payload + 6 + dlen) <= data_end)
                    __builtin_memcpy(evt.dcid, payload+6, 20);
            }
        }
    }
    /* Short header */
    else if (!(payload[0] & 0x80) && (payload[0] & 0x40)) {
        evt.dcid_len = 8;
        __builtin_memcpy(evt.dcid, payload+1, 8);
    }

    if (evt.dcid_len > 0)
        pkt_events.perf_submit(ctx, &evt, sizeof(evt));

    return XDP_PASS;
}
"""

print("Loading XDP program...")
b = BPF(text=XDP_PROG)
fn = b.load_func("track", BPF.XDP)
b.attach_xdp(INTERFACE, fn)
print(f"XDP attached to {INTERFACE}")

# Table 1: DCID -> GCID cache (like quic_cids in paper)
table1_dcid_to_gcid = {}

# Table 2: GCID -> connection state (like quic_lan_map in paper)
# GCID -> {'src_ip': ..., 'src_port': ..., 'orig_port': ...}
table2_quic_conn = {}
dcid_arrival_times = {}

# TA UDP socket
ta_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ta_sock.settimeout(0.05)

stats = {
    "new_conn": 0,
    "migration": 0,
    "lookup": 0,
    "deleted": 0,
}

def ipv4_str(ip_int):
    return socket.inet_ntoa(ip_int.to_bytes(4, 'big'))

def query_ta(dcid_hex):
    """Query Tracking Agent for GCID — Table 1 miss"""
    try:
        ta_sock.sendto(bytes.fromhex(dcid_hex), (TA_IP, TA_PORT))
        data, _ = ta_sock.recvfrom(1024)
        if len(data) == 0:
            return dcid_hex  # TA doesn't know → use DCID as GCID
        return data.hex()
    except:
        return dcid_hex  # timeout → use DCID as GCID

def get_gcid(dcid_hex):
    """
    Table 1 lookup: DCID -> GCID
    Check cache first, then query TA (like quic_cids in paper)
    """
    if dcid_hex in table1_dcid_to_gcid:
        return table1_dcid_to_gcid[dcid_hex]

    # Cache miss - query TA
    gcid = query_ta(dcid_hex)

    # Only cache if TA knows this DCID (real mapping)
    # If TA returns same as DCID, don't cache - try again next time
    if gcid != dcid_hex:
        table1_dcid_to_gcid[dcid_hex] = gcid
        # Merge old DCID-keyed T2 entry into real GCID entry
        if dcid_hex in table2_quic_conn:
            old_entry = table2_quic_conn.pop(dcid_hex)
            if gcid not in table2_quic_conn:
                # Move entry to correct GCID key
                table2_quic_conn[gcid] = old_entry
            else:
                # GCID entry exists - keep it, discard duplicate
                pass
        # Also check all T2 entries that used wrong GCID
        # and remap them
        for wrong_key in list(table2_quic_conn.keys()):
            if table1_dcid_to_gcid.get(wrong_key, wrong_key) == gcid:
                if wrong_key != gcid:
                    entry = table2_quic_conn.pop(wrong_key)
                    if gcid not in table2_quic_conn:
                        table2_quic_conn[gcid] = entry

    return gcid

def delete_conntrack(src_ip, src_port):
    cmd = (f"sudo conntrack -D -p udp "
           f"--src {src_ip} --sport {src_port} "
           f"--dst {SERVER_IP} --dport {SERVER_PORT} 2>/dev/null")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return "1 flow" in result.stdout

def quic_set(src_ip, src_port, gcid):
    # Use src_ip+gcid as key to avoid collisions
    # Use GCID (O-DCID) as key — correct per paper
    table2_key = gcid
    """
    Table 2 operation - exactly like quic_set in paper:
    - If GCID known + different src -> MIGRATION -> UPDATE
    - If GCID known + same src -> LOOKUP
    - If GCID unknown -> NEW CONNECTION -> INSERT
    """
    if table2_key in table2_quic_conn:
        existing = table2_quic_conn[table2_key]
        if existing['src_port'] != src_port or existing['src_ip'] != src_ip:
            # MIGRATION - UPDATE Table 2
            stats["migration"] += 1
            old_port = existing['src_port']
            old_ip = existing['src_ip']

            table2_quic_conn[table2_key] = {
                'src_ip':   src_ip,
                'src_port': src_port,
                'orig_ip':  existing['orig_ip'],
                'orig_port': existing['orig_port'],
            }

            # No conntrack deletion needed
            # Table 2 UPDATE is our solution - one entry per connection!
            pass

            return "Migration"
        else:
            # LOOKUP - same path
            stats["lookup"] += 1
            return "Lookup"
    else:
        # NEW CONNECTION - INSERT into Table 2
        stats["new_conn"] += 1
        table2_quic_conn[table2_key] = {
            'src_ip':   src_ip,
            'src_port': src_port,
            'orig_ip':  src_ip,
            'orig_port': src_port,
        }
        return "New"

def quic_set_with_retry(src_ip, src_port, dcid_hex):
    """Try TA multiple times before giving up"""
    gcid = get_gcid(dcid_hex)
    return quic_set(src_ip, src_port, gcid), gcid

class PktEvent(ctypes.Structure):
    _fields_ = [
        ("src_ip",   ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_ip",   ctypes.c_uint32),
        ("dst_port", ctypes.c_uint16),
        ("dcid_len", ctypes.c_uint8),
        ("dcid",     ctypes.c_uint8 * 20),
    ]

def handle_pkt(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(PktEvent)).contents

    src_ip   = ipv4_str(evt.src_ip)
    src_port = evt.src_port
    dcid_hex = bytes(evt.dcid[:evt.dcid_len]).hex()

    # Wait up to 20ms for T1 to have this DCID via proactive push
    import time as _t
    waited = 0
    while dcid_hex not in table1_dcid_to_gcid and waited < 20:
        _t.sleep(0.001)
        waited += 1

    # Step 1: Table 1 lookup - get GCID for this DCID
    gcid = get_gcid(dcid_hex)

    # Step 2: Table 2 operation - quic_set

    op = quic_set(src_ip, src_port, gcid)

    if op == "Migration":
        if stats["migration"] % 100 == 0:
            print(f'  GCID={gcid} src={src_ip}:{src_port}')
            print(f"\n[Mig#{stats['migration']}] {src_ip}:{src_port} "
                  f"T1:{len(table1_dcid_to_gcid)} T2:{len(table2_quic_conn)} "
                  f"New:{stats['new_conn']}")

# Pre-populate Table 1 from TA
print("Pre-loading Table 1 from Tracking Agent...")
try:
    import urllib.request as ur
    with ur.urlopen(f"http://{TA_IP}:12002/mappings", timeout=3) as r:
        import json
        mappings = json.loads(r.read().decode())
        for dcid, gcid in mappings.items():
            if dcid != gcid:
                table1_dcid_to_gcid[dcid] = gcid
        print(f"Pre-loaded {len(table1_dcid_to_gcid)} mappings into Table 1")
except Exception as e:
    print(f"Could not pre-load: {e}")


import threading as _threading
import json as _json

PUSH_PORT = 13000

def push_listener():
    """Listen for proactive push updates from Tracking Agent"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', PUSH_PORT))
    sock.settimeout(1)
    print(f"Listening for TA push updates on port {PUSH_PORT}")
    while True:
        try:
            data, _ = sock.recvfrom(1024)
            msg = _json.loads(data.decode())
            dcid = msg['dcid']
            gcid = msg['gcid']
            if dcid != gcid:

                table1_dcid_to_gcid[dcid] = gcid
                # Merge T2 entries - move wrong-keyed entry to correct GCID key
                if dcid in table2_quic_conn:
                    entry = table2_quic_conn.pop(dcid)
                    if gcid not in table2_quic_conn:
                        table2_quic_conn[gcid] = entry
                    # else: gcid entry exists, keep it, discard duplicate
                # Also fix any entries that used this dcid as their gcid
                # by checking all T1 mappings pointing to same gcid
                for other_dcid, other_gcid in list(table1_dcid_to_gcid.items()):
                    if other_gcid == gcid and other_dcid in table2_quic_conn:
                        entry = table2_quic_conn.pop(other_dcid)
                        if gcid not in table2_quic_conn:
                            table2_quic_conn[gcid] = entry
        except:
            pass

_t = _threading.Thread(target=push_listener, daemon=True)
_t.start()

b["pkt_events"].open_perf_buffer(handle_pkt, page_cnt=8192)

print("="*60)
print("QUIC-aware NAT — Two Table Implementation")
print(f"Table 1: DCID→GCID cache | Table 2: GCID→connection state")
print("="*60)

try:
    while True:
        b.perf_buffer_poll(timeout=0)
        ct = subprocess.run("sudo conntrack -C",
                           shell=True, capture_output=True, text=True).stdout.strip()
        print(f"\rCT:{ct} | New:{stats['new_conn']} "
              f"Mig:{stats['migration']} Lookup:{stats['lookup']} "
              f"Del:{stats['deleted']} | "
              f"T1:{len(table1_dcid_to_gcid)} T2:{len(table2_quic_conn)}",
              end="\n", flush=True)
except KeyboardInterrupt:
    print("\nStopping...")
    b.remove_xdp(INTERFACE, 0)
    print(f"Final: {stats}")
    print(f"Table 1 (DCID→GCID): {len(table1_dcid_to_gcid)} entries")
    print(f"Table 2 (GCID→conn): {len(table2_quic_conn)} entries")
