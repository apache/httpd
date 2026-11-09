#!/usr/bin/env python3
import os, sys, time
from urllib.parse import parse_qs

# Answer once the file named in the query string exists.
path = parse_qs(os.environ.get("QUERY_STRING", ""))["file"][0]
deadline = time.time() + 60
while not os.path.exists(path) and time.time() < deadline:
    time.sleep(0.05)

print("Status: 200")
print("Content-Type: text/plain\n")
sys.stdout.write("released\n")
