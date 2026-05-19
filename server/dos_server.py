import argparse
import asyncio
import logging
import struct
from typing import Dict, Optional
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from aioquic.tls import SessionTicket

logger = logging.getLogger("server")

class DosServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.migration_count = 0
    
    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            try:
                length = struct.unpack("!H", bytes(event.data[:2]))[0]
                data = int.from_bytes(event.data[2 : 2 + length], "big")
                self.migration_count += 1
                
                if self.migration_count % 1000 == 0:
                    logger.info(f"Received {self.migration_count} migrations")
                    
            except Exception as e:
                logger.error(f"Error processing data: {e}")

class SessionTicketStore:
    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}
    
    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket
    
    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)

async def main(host: str, port: int, configuration: QuicConfiguration, session_ticket_store: SessionTicketStore) -> None:
    logger.info(f"Starting QUIC server on {host}:{port}")
    
    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=DosServerProtocol,
        session_ticket_fetcher=session_ticket_store.pop,
        session_ticket_handler=session_ticket_store.add,
    )
    
    await asyncio.Future()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QUIC Migration DoS Server")
    parser.add_argument("--host", type=str, default="::", help="Listen address (default: ::)")
    parser.add_argument("--port", type=int, default=4444, help="Listen port (default: 4444)")
    parser.add_argument("-k", "--private-key", type=str, help="TLS private key file")
    parser.add_argument("-c", "--certificate", type=str, required=True, help="TLS certificate file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    
    configuration = QuicConfiguration(alpn_protocols=["dos-demo"], is_client=False)
    configuration.load_cert_chain(args.certificate, args.private_key)
    
    try:
        asyncio.run(
            main(
                host=args.host,
                port=args.port,
                configuration=configuration,
                session_ticket_store=SessionTicketStore(),
            )
        )
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
