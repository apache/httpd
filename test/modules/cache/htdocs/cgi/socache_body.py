#!/usr/bin/env python3
import time
body = f"time={time.time()}\n"
print("Content-Type: text/plain")
print("Cache-Control: must-revalidate, max-age=10")
print("Vary: Accept-Encoding")
print(f"Content-Length: {len(body)}")
print()
print(body, end="")
