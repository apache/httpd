#!/usr/bin/env python3
import sys

body = sys.stdin.buffer.read()
sys.stdout.buffer.write(b"Content-Type: application/octet-stream\r\n")
sys.stdout.buffer.write(f"X-Request-Length: {len(body)}\r\n\r\n".encode())
sys.stdout.buffer.write(body)
