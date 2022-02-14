#!/usr/bin/env python3
import random
import sys
import time
from datetime import timedelta

random.seed()
to_write = total_len = random.randint(1, 10*1024*1024)

sys.stdout.write("Content-Type: application/octet-stream\n")
sys.stdout.write(f"Content-Length: {total_len}\n")
sys.stdout.write("\n")
sys.stdout.flush()

while to_write > 0:
    len = random.randint(1, 1024*1024)
    len = min(len, to_write)
    sys.stdout.buffer.write(random.randbytes(len))
    to_write -= len
    delay = timedelta(seconds=random.uniform(0.0, 0.5))
    time.sleep(delay.total_seconds())
sys.stdout.flush()

