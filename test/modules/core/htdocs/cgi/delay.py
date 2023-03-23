#!/usr/bin/env python3
import sys, time

content="A delayed response.\n"

print("Status: 200")
print(f"Request-Length: {len(content)}")
print("Content-Type: text/plain\n")
time.sleep(1)
sys.stdout.write(content)

