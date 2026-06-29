#!/usr/bin/env python3
from bcc import BPF
import ctypes
import socket
import subprocess
import time
import threading as _threading
import json as _json
from concurrent.futures import ThreadPoolExecutor

INTERFACE   = "ens18"
SERVER_IP   = "172.16.20.112"
SERVER_PORT = 4444
TA_IP       = "172.16.0.113"
TA_PORT     = 12001
PUSH_PORT   = 13000

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

table1_dcid_to_gcid = {}
table2_quic_conn = {}
pending_queue = {}
pending_queue_lock = set()
_pull_executor = ThreadPoolExecutor(max_workers=64)

stats = {"new_conn": 0, "migration": 0, "lookup": 0, "deleted": 0}

def ipv4_str(ip_int):
    return socket.inet_ntoa(ip_int.to_bytes(4, 'big'))

ta_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ta_sock.settimeout(0.02)

def query_ta(dcid_hex):
    try:
        ta_sock.sendto(bytes.fromhex(dcid_hex), (TA_IP, TA_PORT))
        data, _ = ta_sock.recvfrom(1024)
        if len(data) == 0:
            return dcid_hex
        return data.hex()
    except:
        return dcid_hex

def pull_and_drain(dcid_hex):
    import time as _time
    gcid = dcid_hex
    for _ in range(50):
        result = query_ta(dcid_hex)
        if result != dcid_hex:
            gcid = result
            table1_dcid_to_gcid[dcid_hex] = gcid
            break
        _time.sleep(0.001)
    events = pending_queue.pop(dcid_hex, None)
    if events:
        for (src_ip, src_port) in events:
            quic_set(src_ip, src_port, gcid)
    pending_queue_lock.discard(dcid_hex)

def quic_set(src_ip, src_port, gcid):
    table2_key = gcid
    if table2_key in table2_quic_conn:
        existing = table2_quic_conn[table2_key]
        if existing['src_port'] != src_port or existing['src_ip'] != src_ip:
            stats["migration"] += 1
            all_paths = existing.get('all_paths', [(existing['orig_ip'], existing['orig_port'])])
            if (src_ip, src_port) not in all_paths:
                all_paths.append((src_ip, src_port))
            table2_quic_conn[table2_key] = {
                'src_ip': src_ip, 'src_port': src_port,
                'orig_ip': existing['orig_ip'], 'orig_port': existing['orig_port'],
                'all_paths': all_paths,
            }
            return "Migration"
        else:
            stats["lookup"] += 1
            return "Lookup"
    else:
        stats["new_conn"] += 1
        table2_quic_conn[table2_key] = {
            'src_ip': src_ip, 'src_port': src_port,
            'orig_ip': src_ip, 'orig_port': src_port,
            'all_paths': [(src_ip, src_port)],
        }
        return "New"

class PktEvent(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32), ("src_port", ctypes.c_uint16),
        ("dst_ip", ctypes.c_uint32), ("dst_port", ctypes.c_uint16),
        ("dcid_len", ctypes.c_uint8), ("dcid", ctypes.c_uint8 * 20),
    ]

_latency_file = open('/home/ayushmanmb/results/latencies.txt', 'w', buffering=1)
_latency_file.write("dcid_status latency_us\n")

def handle_pkt(cpu, data, size):
    import time
    _start = time.perf_counter()
    evt = ctypes.cast(data, ctypes.POINTER(PktEvent)).contents
    src_ip   = ipv4_str(evt.src_ip)
    src_port = evt.src_port
    dcid_hex = bytes(evt.dcid[:evt.dcid_len]).hex()

    if dcid_hex in table1_dcid_to_gcid:
        gcid = table1_dcid_to_gcid[dcid_hex]
        op = quic_set(src_ip, src_port, gcid)
        _lat = (time.perf_counter() - _start) * 1e6
        _latency_file.write(f"hit {_lat:.2f}\n")
        if op == "Migration" and stats["migration"] % 100 == 0:
            print(f"\n[Mig#{stats['migration']}] {src_ip}:{src_port} "
                  f"T1:{len(table1_dcid_to_gcid)} T2:{len(table2_quic_conn)} "
                  f"New:{stats['new_conn']}")
        return

    if dcid_hex not in pending_queue:
        pending_queue[dcid_hex] = []
    pending_queue[dcid_hex].append((src_ip, src_port))
    if dcid_hex not in pending_queue_lock:
        pending_queue_lock.add(dcid_hex)
        _pull_executor.submit(pull_and_drain, dcid_hex)
    _lat = (time.perf_counter() - _start) * 1e6
    _latency_file.write(f"miss {_lat:.2f}\n")

def push_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', PUSH_PORT))
    sock.settimeout(1)
    print(f"Listening for TA push on port {PUSH_PORT}")
    while True:
        try:
            data, _ = sock.recvfrom(1024)
            msg = _json.loads(data.decode())
            dcid = msg['dcid']
            gcid = msg['gcid']
            # DEBUG
            stats.setdefault("push_recv", 0)
            stats["push_recv"] += 1
            if dcid != gcid:
                import time as _t5
                _T5 = _t5.time()
                try:
                    import socket as _s5
                    _ts = _s5.socket(_s5.AF_INET, _s5.SOCK_DGRAM)
                    _ts.sendto(f"T5 {_T5:.6f}".encode(), ("127.0.0.1", 19999))
                    _ts.close()
                except:
                    pass
                table1_dcid_to_gcid[dcid] = gcid
                stats.setdefault("push_merged", 0)
                
                # Case 1: T2 has entry keyed by dcid → move to gcid
                if dcid in table2_quic_conn:
                    stats["push_merged"] += 1
                    entry = table2_quic_conn.pop(dcid)
                    if gcid not in table2_quic_conn:
                        table2_quic_conn[gcid] = entry
                
                # Case 2: T2 already has gcid entry — just update T1
                # (entry already correctly keyed, nothing to move)
                
                # Case 3: Scan ALL T2 entries for any that should map to gcid
                # This handles entries created via pull_and_drain with wrong gcid
                for t2_key in list(table2_quic_conn.keys()):
                    if t2_key == gcid:
                        continue  # already correct
                    # Check if this T2 entry's key is a DCID that maps to gcid
                    if table1_dcid_to_gcid.get(t2_key) == gcid:
                        stats["push_merged"] += 1
                        entry = table2_quic_conn.pop(t2_key)
                        if gcid not in table2_quic_conn:
                            table2_quic_conn[gcid] = entry
                        break
        except:
            pass

print("Pre-loading Table 1 from Tracking Agent...")
try:
    import urllib.request as ur
    with ur.urlopen(f"http://{TA_IP}:12002/mappings", timeout=3) as r:
        mappings = _json.loads(r.read().decode())
        for dcid, gcid in mappings.items():
            if dcid != gcid:
                import time as _t5
                _T5 = _t5.time()
                try:
                    import socket as _s5
                    _ts = _s5.socket(_s5.AF_INET, _s5.SOCK_DGRAM)
                    _ts.sendto(f"T5 {_T5:.6f}".encode(), ("127.0.0.1", 19999))
                    _ts.close()
                except:
                    pass
                table1_dcid_to_gcid[dcid] = gcid
        print(f"Pre-loaded {len(table1_dcid_to_gcid)} mappings into Table 1")
except Exception as e:
    print(f"Could not pre-load: {e}")

_pt = _threading.Thread(target=push_listener, daemon=True)
_pt.start()

b["pkt_events"].open_perf_buffer(handle_pkt, page_cnt=8192)

print("="*60)
print("QUIC-aware Connection Tracking — Pull Model")
print(f"Interface: {INTERFACE} | Server: {SERVER_IP}:{SERVER_PORT}")
print(f"Table 1: DCID->GCID | Table 2: GCID->connection state")
print("="*60)

try:
    _loop_count = 0
    _last_ct = "0"
    while True:
        b.perf_buffer_poll(timeout=0)
        _loop_count += 1
        if _loop_count % 10000 != 0:
            continue
        _last_ct = subprocess.run("sudo conntrack -C",
                           shell=True, capture_output=True, text=True).stdout.strip()
        ct = _last_ct
        push_recv = stats.get('push_recv', 0)
        push_merged = stats.get('push_merged', 0)
        import sys
        # Write to stderr for live view
        sys.stderr.write(f"CT:{ct} | New:{stats['new_conn']} "
              f"Mig:{stats['migration']} Lookup:{stats['lookup']} | "
              f"T1:{len(table1_dcid_to_gcid)} T2:{len(table2_quic_conn)} | "
              f"Push:{push_recv} Merged:{push_merged}\n")
        # Write stats to file for logger
        with open('/tmp/mb_stats.txt', 'w') as _sf:
            _sf.write(f"CT:{ct} T1:{len(table1_dcid_to_gcid)} T2:{len(table2_quic_conn)}\n")
        # Append time-series to file for gnuplot
        if not hasattr(sys, '_log_file'):
            sys._log_file = open('/home/ayushmanmb/results/timeseries.txt', 'w')
            sys._log_file.write("time ct new mig lookup t1 t2 push merged drops\n")
            sys._log_start = time.time()
        elapsed = int(time.time() - sys._log_start)
        # Count kernel drops
        try:
            drops = int(subprocess.run("sudo dmesg | grep -c 'table full'", shell=True, capture_output=True, text=True).stdout.strip())
        except:
            drops = 0
        sys._log_file.write(f"{elapsed} {ct} {stats['new_conn']} {stats['migration']} {stats['lookup']} {len(table1_dcid_to_gcid)} {len(table2_quic_conn)} {push_recv} {push_merged} {drops}\n")
        sys._log_file.flush()
except KeyboardInterrupt:
    print("\nStopping...")
    b.remove_xdp(INTERFACE, 0)
    print(f"Final: {stats}")
    print(f"T1: {len(table1_dcid_to_gcid)} | T2: {len(table2_quic_conn)}")
