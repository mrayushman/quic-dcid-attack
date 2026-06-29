import socket
import pickle
from threading import Thread
import os
import time
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

def print(*args):
    with open("logs/agent_log.txt", "a") as f:
        for arg in args:
            f.write(str(arg) + " ")
        f.write("\n")

class Mapping:
    def __init__(self):
        self.data = {}

    def store(self, global_cid, new_cid):
        self.data[new_cid] = global_cid
        # pass
    
    def get(self, new_cid):
        if new_cid in self.data.keys():
            return self.data[new_cid]
        
        return None

    def print_all(self):
        while True:
            with open("logs/agent_mappings.txt", "w") as f:
                now = datetime.datetime.now()
                f.write("Last Updated: "+ str(now) +"\n")
                f.write("No of mappings:" + str(len(self.data)) + "\n")
                bound_line = "-"*55
                line = "|{:^25} | {:^25} |".format("DCID", "GCID")
                f.write(bound_line + "\n")
                f.write(line + "\n")
                f.write(bound_line + "\n")
                for key, value in list(self.data.items()):
                    line = "|{:^25} | {:^25} |".format(key.hex(), value.hex())
                    # f.write(bound_line + "\n")
                    f.write(line + "\n")
                    f.write(bound_line + "\n")
            time.sleep(0.1)

class Configuration:
    def __init__(self, original_cid, peer_cid):
        self.original_cid = original_cid
        self.peer_cid = peer_cid
class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/count':
            count = str(len(mapping.data))
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(count.encode())
        elif self.path == '/metrics':
            metrics = f"""# HELP tracking_agent_mappings Total DCID mappings
# TYPE tracking_agent_mappings gauge
tracking_agent_mappings {len(mapping.data)}
"""
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(metrics.encode())
        elif self.path == '/mappings':
            import json
            data = {
                dcid.hex(): gcid.hex()
                for dcid, gcid in mapping.data.items()
            }
            response = json.dumps(data).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(response)

    def log_message(self, format, *args):
        pass


import json as _json

MIDDLEBOX_IP = "172.16.0.129"
MIDDLEBOX_PORT = 13000

# Persistent push socket — created once, reused
_push_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def push_to_middlebox(dcid_hex, gcid_hex):
    try:
        msg = _json.dumps({"dcid": dcid_hex, "gcid": gcid_hex}).encode()
        _push_sock.sendto(msg, (MIDDLEBOX_IP, MIDDLEBOX_PORT))
    except:
        pass

def store_cid(message):
    data = pickle.loads(message)
    mapping.store(data.original_cid, data.peer_cid)
    import time as _t4
    _T4 = _t4.time()
    import socket as _s4
    try:
        _ts = _s4.socket(_s4.AF_INET, _s4.SOCK_DGRAM)
        _ts.sendto(f"T4 {_T4:.6f}".encode(), ("172.16.0.129", 19999))
        _ts.close()
    except:
        pass
    push_to_middlebox(data.peer_cid.hex(), data.original_cid.hex())

def get_cid(message):
    cid = message
    global_cid = mapping.get(cid)
    return global_cid
    

def post_config_thread():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('', 12000))

    while True:
        message, address = server_socket.recvfrom(1024)
        store_cid(message)
    
def get_config_thread():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('', 12001))

    while True:
        message, address = server_socket.recvfrom(1024)
        # print("Received Request message: ", message.hex())
        global_cid = get_cid(message)
        
        if global_cid is not None:
            # print("Sending global_cid: ", global_cid.hex())
            server_socket.sendto(global_cid, address)
        else:
            # print("Sending None global_cid")
            server_socket.sendto(bytes(0), address)

def main():
    try:
        os.mkdir("logs")
    except FileExistsError:
        pass
    
    with open("logs/agent_log.txt", "w") as f:
        f.write("")

    thread1 = Thread(target=get_config_thread)
    thread2 = Thread(target=post_config_thread)
   
    def print_all_mappings():
        while True:
            mapping.print_all()
            time.sleep(1)
   
    thread3 = Thread(target=print_all_mappings)
    def http_server_thread():
        server = HTTPServer(('0.0.0.0', 12002), MetricsHandler)
        server.serve_forever()
    
    thread4 = Thread(target=http_server_thread)
    thread4 = Thread(target=http_server_thread)

    print("Starting threads...")
    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread1.join()
    thread2.join()
    thread3.join()

if __name__ == "__main__":
    mapping = Mapping()
    main()

# Push updates to registered middleboxes