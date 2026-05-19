from bcc import BPF
import socket
import ctypes
import time
import os

import pickle

class Configuration:
    def __init__(self, original_cid, peer_cid):
        self.original_cid = original_cid
        self.peer_cid = peer_cid

def send_to_agent(o_dcid, dcid, agent_ip='127.0.0.1', agent_port=9999):
    """Send DCID → O-DCID mapping to Tracking Agent"""
    try:
        print(f"[DEBUG] Sending to agent: O-DCID={o_dcid.hex()[:16]}... DCID={dcid.hex()[:16]}...")
        config = Configuration(o_dcid, dcid)
        message = pickle.dumps(config)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message, (agent_ip, agent_port))
        sock.close()
        print(f"[DEBUG] Sent successfully!")
    except Exception as e:
        print(f"[DEBUG] Error: {e}")

with open("endpoint_dcid.c", "r") as f:
    bpf_program = f.read()
bpf = BPF(text=bpf_program)
fn = bpf.load_func("ingress_xdp", BPF.XDP)
bpf.attach_xdp("ens18", fn)
bpf.attach_kprobe(event="udp_send_skb", fn_name="trace_udp_send_skb")

def ipv4_to_str(ip):
    return socket.inet_ntoa(ctypes.c_uint32(ip).value.to_bytes(4, 'big'))

class QUICEventKey(ctypes.Structure):
    _fields_ = [("sip",ctypes.c_uint32),("dip",ctypes.c_uint32),
                ("sport",ctypes.c_uint16),("dport",ctypes.c_uint16)]
class QUICEvent(ctypes.Structure):
    _fields_ = [("dcid_length",ctypes.c_ubyte),("dcid",ctypes.c_ubyte*20),
                ("scid_length",ctypes.c_ubyte),("scid",ctypes.c_ubyte*20),
                ("first_dcid",ctypes.c_ubyte*20),("timestamp",ctypes.c_uint64)]
class DcidKey(ctypes.Structure):
    _fields_ = [("dcid_length",ctypes.c_ubyte),("dcid",ctypes.c_ubyte*20)]
class DcidValue(ctypes.Structure):
    _fields_ = [("scid_length",ctypes.c_ubyte),("first_dcid",ctypes.c_ubyte*20)]

def hexid(arr, length):
    return "".join(f"{b:02x}" for b in arr[:length])

def trim_odcid(arr):
    """Strip trailing zero bytes from first_dcid and return hex string."""
    b = bytes(arr[:20]).rstrip(b'\x00')
    return b.hex() if b else "00"

SERVER_PORT = 4444

def print_migration_table(bpf):
    groups = {}

    def add(odcid, dcid, path):
        if odcid not in groups:
            groups[odcid] = {"dcids": [], "paths": []}
        g = groups[odcid]
        if dcid and dcid not in g["dcids"]:
            g["dcids"].append(dcid)
            #Sending to Tracking agent
            try:
                send_to_agent(bytes.fromhex(odcid), bytes.fromhex(dcid))
            except:
                pass
        if path and path not in g["paths"]:
            g["paths"].append(path)

    # Step 1: connections_map, client->server only
    for kb, vb in bpf["connections_map"].items():
        k = QUICEventKey.from_buffer_copy(kb)
        v = QUICEvent.from_buffer_copy(vb)
        if k.dport != SERVER_PORT:
            continue
        odcid = trim_odcid(v.first_dcid)   # strip zero padding
        dcid  = hexid(v.dcid, v.dcid_length)
        path  = f"{ipv4_to_str(k.sip)}:{k.sport}  ->  {ipv4_to_str(k.dip)}:{k.dport}"
        add(odcid, dcid, path)

    # Step 2: dcids_map — all historical DCIDs, matched by trimmed ODCID
    for kb, vb in bpf["dcids_map"].items():
        k = DcidKey.from_buffer_copy(kb)
        v = DcidValue.from_buffer_copy(vb)
        odcid = trim_odcid(v.first_dcid)   # same trim — keys now match
        dcid  = hexid(k.dcid, k.dcid_length)
        if odcid in groups:                 # only attach to known connections
            add(odcid, dcid, "")

   # os.system("clear")

    if not groups:
        print("\n  Tracing... No QUIC connections seen yet.\n")
        return

    max_w = max((len(o) for o in groups), default=16)
    W1 = max(max_w, len("ODCID (First DCID)"))
    W2 = 34
    W3 = 46

    SEP = f"  {'─'*W1}─┼─{'─'*W2}─┼─{'─'*W3}"
    HDR = (f"  {'ODCID (First DCID)':<{W1}} │ "
           f"  {'Associated DCIDs  (rotations)':<{W2}} │ "
           f"  {'IP:Port Paths  (migrations)':<{W3}}")

    ts = time.strftime('%H:%M:%S')
    print(f"╔══ LinkQUIC Migration Tracker ══ {ts} ══")
    print(HDR)
    print(SEP)

    total_conns = total_dcids = total_paths = migrations = 0

    for odcid in sorted(groups.keys()):
        dcids = groups[odcid]["dcids"]
        paths = groups[odcid]["paths"]
        nrows = max(len(dcids), len(paths), 1)

        srcs     = set(p.split("  ->  ")[0].strip() for p in paths)
        migrated = len(srcs) > 1

        total_conns += 1
        total_dcids += len(dcids)
        total_paths += len(paths)
        if migrated:
            migrations += 1

        tag = "  ◄◄ MIGRATION" if migrated else ""

        for i in range(nrows):
            col1 = odcid    if i == 0 else " " * W1
            col2 = dcids[i] if i < len(dcids) else ""
            col3 = paths[i] if i < len(paths) else ""
            flag = tag      if i == 0 else ""
            note = "  (new path)" if (migrated and i > 0 and i < len(paths)) else ""
            print(f"  {col1:<{W1}} │   {col2:<{W2}} │   {col3:<{W3}}{flag}{note}")

        print(SEP)

    print(f"\n  Connections: {total_conns}  |  "
          f"DCIDs seen: {total_dcids}  |  "
          f"Paths seen: {total_paths}  |  "
          f"Migrations: {migrations}\n")

print("Tracing... Press Ctrl+C to stop.")

import ctypes as ct

class DcidEvent(ct.Structure):
    _fields_ = [
        ("dcid_length", ct.c_uint8),
        ("dcid", ct.c_uint8 * 20),
        ("first_dcid", ct.c_uint8 * 20),
    ]

def handle_dcid_event(cpu, data, size):
    evt = ct.cast(data, ct.POINTER(DcidEvent)).contents
    dcid = bytes(evt.dcid[:evt.dcid_length]).hex()
    first_dcid = bytes(evt.first_dcid[:evt.dcid_length]).hex()
    if dcid and first_dcid:
        send_to_agent(bytes.fromhex(first_dcid), bytes.fromhex(dcid))

bpf["dcid_events"].open_perf_buffer(handle_dcid_event, page_cnt=4096)

try:
    while True:
        bpf.perf_buffer_poll(timeout=1)
        print_migration_table(bpf)
        time.sleep(0.001)
except KeyboardInterrupt:
    pass
