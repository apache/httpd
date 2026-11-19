#!/usr/bin/env python3
import os
import sys
import time
from urllib.parse import parse_qs

# Answer with the status given in the query and always try to send a body,
# in as many flushed parts as asked for. Write bytes: text mode would turn
# every "\n" into "\r\n" on Windows.
query = parse_qs(os.environ.get("QUERY_STRING", ""))
status = query.get("status", ["200"])[0]
parts = int(query.get("parts", ["1"])[0])

out = sys.stdout.buffer
out.write(f"Status: {status}\r\nContent-Type: text/plain\r\n\r\n".encode())
for _ in range(parts):
    out.write(b"SHOULD-NOT-BE-SENT\n")
    out.flush()
    if parts > 1:
        time.sleep(0.1)
