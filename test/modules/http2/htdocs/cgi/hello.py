#!/usr/bin/env python3

import os
import json

resp = {
    'https': os.getenv('HTTPS', ''),
    'host': os.getenv('X_HOST', '') if 'X_HOST' in os.environ else os.getenv('SERVER_NAME', ''),
    'server': os.getenv('SERVER_NAME', ''),
    'h2_original_host': os.getenv('H2_ORIGINAL_HOST', ''),
    'port': os.getenv('SERVER_PORT', ''),
    'protocol': os.getenv('SERVER_PROTOCOL', ''),
    'ssl_protocol': os.getenv('SSL_PROTOCOL', ''),
    'h2': os.getenv('HTTP2', ''),
    'h2push': os.getenv('H2PUSH', ''),
    'h2_stream_id': os.getenv('H2_STREAM_ID', ''),
    'x-forwarded-for': os.getenv('HTTP_X_FORWARDED_FOR', ''),
    'x-forwarded-host': os.getenv('HTTP_X_FORWARDED_HOST', ''),
    'x-forwarded-server': os.getenv('HTTP_X_FORWARDED_SERVER', ''),
}

print("Content-Type: application/json")
print()
print(json.JSONEncoder(indent=2).encode(resp))

