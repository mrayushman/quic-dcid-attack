import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 19999))
sock.settimeout(1)
print("Collecting timestamps on localhost:19999...")

import sys
outfile = sys.argv[1] if len(sys.argv) > 1 else '/tmp/timestamps.txt'
with open(outfile, 'w') as f:
    f.write("stage timestamp\n")
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            msg = data.decode().strip()
            f.write(f"{msg}\n")
            f.flush()
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            break
print("Done!")
