#!/usr/bin/env python3
import sys
import time

out = sys.stdout.buffer
out.write(b"Content-Type: application/octet-stream\r\n\r\nfirst\n")
out.flush()
time.sleep(2)
out.write(b"second\n")
