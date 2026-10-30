#!/usr/bin/env python3
import sys

# echo the request body back, byte for byte
data = sys.stdin.buffer.read()
sys.stdout.buffer.write(b"Content-Type: application/octet-stream\r\n")
sys.stdout.buffer.write(b"\r\n")
sys.stdout.buffer.write(data)
sys.stdout.buffer.flush()
