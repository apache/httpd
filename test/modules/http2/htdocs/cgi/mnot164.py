#!/usr/bin/env python3
import os, sys
from requestparser import get_request_params


forms, files = get_request_params()
text = forms['text'] if 'text' in forms else "a"
count = int(forms['count']) if 'count' in forms else 77784

print("Status: 200 OK")
print("Content-Type: text/html")
print()
sys.stdout.flush()
for _ in range(count):
    sys.stdout.write(text)

