import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('172.16.0.129', 19999))
sock.settimeout(1)
print("Collecting timestamps on 172.16.0.129:19999...")

with open('/home/ayushmanmb/results/timestamps_qlog.txt', 'w') as f:
    f.write("stage timestamp\n")
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            msg = data.decode().strip()
            f.write(f"{msg}\n")
            f.flush()
            print(f"  {msg}")
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            break
print("Done!")
