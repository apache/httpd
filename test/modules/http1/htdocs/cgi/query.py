#!/usr/bin/env python3
# Echo a QUERY (RFC 10008) request back as JSON, with fixed validators
# so that conditional requests can be tested.
import json
import os
import sys

length = int(os.getenv('CONTENT_LENGTH', '0') or '0')
body = sys.stdin.buffer.read(length) if length > 0 else b''

print("Content-Type: application/json")
print('ETag: "query-1"')
print("Last-Modified: Sun, 31 Aug 2025 08:44:00 GMT")
print()
print(json.dumps({
    "method": os.getenv('REQUEST_METHOD', ''),
    "content_type": os.getenv('CONTENT_TYPE', ''),
    "query_string": os.getenv('QUERY_STRING', ''),
    "body": body.decode('utf-8', errors='replace'),
}))
