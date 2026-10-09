#!/usr/bin/env python3

import os
import json

print("Content-Type: application/json")
print()

data = {
    "REQUEST_METHOD": os.getenv("REQUEST_METHOD", ""),
    "QUERY_STRING": os.getenv("QUERY_STRING", ""),
    "HTTP_PROXY": os.getenv("HTTP_PROXY", ""),
}

print(json.dumps(data, indent=2))
