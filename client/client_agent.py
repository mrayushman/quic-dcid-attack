#!/usr/bin/env python3
"""
Client Agent for QUIC Migration Detection
Receives data from:
  - eBPF (endpoint.py) 
  - QLOG Parser (qlog_parser.py)
Forwards to Tracking Agent (172.16.0.113:12000)
"""

import socket
import pickle
import logging
import os
from threading import Thread
from datetime import datetime

# Setup logging
os.makedirs('/home/ayushman/logs', exist_ok=True)
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.CRITICAL,
    handlers=[
        logging.FileHandler("/home/ayushman/logs/client_agent_log.txt"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("client_agent")

# Client Agent listens on this port
LISTEN_PORT = 9999

# Tracking Agent address
TRACKING_AGENT_IP = "172.16.0.113"
TRACKING_AGENT_PORT = 12000

class Configuration:
    def __init__(self, original_cid, peer_cid):
        self.original_cid = original_cid
        self.peer_cid = peer_cid

def forward_to_tracking_agent(original_cid, peer_cid, source="unknown"):
    """Forward DCID mapping to Tracking Agent"""
    try:
        config = Configuration(original_cid, peer_cid)
        message = pickle.dumps(config)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message, (TRACKING_AGENT_IP, TRACKING_AGENT_PORT))
        sock.close()
        logger.info(f"[{source}] Forwarded: {peer_cid.hex()} -> {original_cid.hex()}")
        return True
    except Exception as e:
        logger.error(f"Failed to forward to Tracking Agent: {e}")
        return False

def listen_thread():
    """Listen for incoming mappings from eBPF or QLOG Parser"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', LISTEN_PORT))
    logger.info(f"Listening on port {LISTEN_PORT}...")

    total_received = 0

    while True:
        try:
            message, address = server_socket.recvfrom(4096)
            data = pickle.loads(message)

            original_cid = data.original_cid
            peer_cid = data.peer_cid

            # Determine source
            #source = "eBPF" if address[0] != "127.0.0.1" else "QLOG"
            source = "eBPF" if address[1] != 0 and address[0] == "127.0.0.1" else "QLOG"

            total_received += 1

            logger.info(f"[{source}] Received #{total_received}: "
                       f"DCID={peer_cid.hex()} ODCID={original_cid.hex()}")

            # Forward to Tracking Agent
            forward_to_tracking_agent(original_cid, peer_cid, source)

        except Exception as e:
            logger.error(f"Error processing message: {e}")

def main():
    logger.info("="*50)
    logger.info("Client Agent Started")
    logger.info(f"Listening on: 0.0.0.0:{LISTEN_PORT}")
    logger.info(f"Forwarding to: {TRACKING_AGENT_IP}:{TRACKING_AGENT_PORT}")
    logger.info("Sources: eBPF + QLOG Parser")
    logger.info("="*50)

    t = Thread(target=listen_thread)
    t.daemon = True
    t.start()
    t.join()

if __name__ == "__main__":
    main()
