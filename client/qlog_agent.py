import os, json, time, socket, pickle, glob

QLOG_DIR = "/tmp/qlog"
AGENT_PORT = 9999
sent = set()

class Configuration:
    def __init__(self, original_cid, peer_cid):
        self.original_cid = original_cid
        self.peer_cid = peer_cid

def send_to_agent(o_dcid, dcid):
    try:
        import time as _t
        _T2 = _t.time()
        _ts = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _ts.sendto(f"T2 {_T2:.6f}".encode(), ("127.0.0.1", 19999))
        _ts.close()
        config = Configuration(
            bytes.fromhex(o_dcid),
            bytes.fromhex(dcid)
        )
        msg = pickle.dumps(config)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg, ('127.0.0.1', AGENT_PORT))
        _T3 = _t.time()
        _ts = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _ts.sendto(f"T3 {_T3:.6f}".encode(), ("127.0.0.1", 19999))
        _ts.close()
        sock.close()
    except Exception as e:
        print(f"Error: {e}")

def parse_qlog(filepath):
    try:
        with open(filepath) as f:
            data = json.load(f)
        
        for trace in data.get('traces', []):
            odcid = trace.get('common_fields', {}).get('ODCID', '')
            if not odcid:
                continue
            
            for event in trace.get('events', []):
                name = event.get('name', '')
                # Look for connection ID updates
                if 'connection_id' in name or 'spin_bit' in name:
                    edata = event.get('data', {})
                    dcid = edata.get('connection_id', '')
                    if dcid and odcid and (odcid, dcid) not in sent:
                        send_to_agent(odcid, dcid)
                        sent.add((odcid, dcid))
                        print(f"[QLOG] O-DCID={odcid[:8]} DCID={dcid[:8]}")
                
                # Also capture initial connection
                if name == 'transport:parameters_set':
                    if (odcid, odcid) not in sent:
                        send_to_agent(odcid, odcid)
                        sent.add((odcid, odcid))
                        print(f"[QLOG] Initial O-DCID={odcid[:8]}")
    except Exception as e:
        print(f"Parse error {filepath}: {e}")

print(f"Watching {QLOG_DIR} for qlog files...")
while True:
    for f in glob.glob(f"{QLOG_DIR}/*.qlog"):
        parse_qlog(f)
    time.sleep(0.5)
