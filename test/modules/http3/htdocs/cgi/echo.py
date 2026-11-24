#!/usr/bin/env python3
import json
import os
import sys

content = sys.stdin.buffer.read()
names = ["REQUEST_METHOD", "SERVER_PROTOCOL", "SERVER_NAME", "HTTPS",
         "CONTENT_TYPE", "CONTENT_LENGTH", "QUERY_STRING"]
result = {n.lower(): os.environ.get(n, "") for n in names}
result["body_len"] = len(content)
result["body_tail"] = content[-16:].decode("latin-1")
sys.stdout.write("Content-Type: application/json\n\n")
sys.stdout.write(json.dumps(result))
