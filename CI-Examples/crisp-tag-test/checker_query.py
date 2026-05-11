#!/usr/bin/env python3
# Usage: ./checker_query.py [port] [num_queries]
# Run while a gramine process with CRISP enabled is listening on the checker port.

import socket
import struct
import sys
import time

HOST = "localhost"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 19999
QUERIES = int(sys.argv[2]) if len(sys.argv) > 2 else 1
DEADLINE = 10.0  # seconds to keep retrying connect

def query():
    # Checker drains until S >= L, then sends 8 bytes (uint64 MC, little-endian).
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        data = b""
        while len(data) < 8:
            chunk = s.recv(8 - len(data))
            if not chunk:
                break
            data += chunk
    return struct.unpack("<Q", data)[0] if len(data) == 8 else None

start = time.time()
for i in range(QUERIES):
    while True:
        try:
            mc = query()
            print(f"query {i + 1}: MC = {mc}")
            break
        except (ConnectionRefusedError, socket.timeout, OSError):
            if time.time() - start > DEADLINE:
                print(f"query {i + 1}: checker not reachable on {HOST}:{PORT}")
                sys.exit(1)
            time.sleep(0.1)
