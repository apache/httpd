#!/usr/bin/env python3

import os

print("Content-Type: application/json")
print()
print("{")
print("  \"https\" : \"%s\"," % (os.getenv('HTTPS', '')))
print("  \"host\" : \"%s\"," % (os.getenv('X_HOST', '') \
    if 'X_HOST' in os.environ else os.getenv('SERVER_NAME', '')))
print("  \"server\" : \"%s\"," % (os.getenv('SERVER_NAME', '')))
print("  \"h2_original_host\" : \"%s\"," % (os.getenv('H2_ORIGINAL_HOST', '')))
print("  \"port\" : \"%s\"," % (os.getenv('SERVER_PORT', '')))
print("  \"protocol\" : \"%s\"," % (os.getenv('SERVER_PROTOCOL', '')))
print("  \"ssl_protocol\" : \"%s\"," % (os.getenv('SSL_PROTOCOL', '')))
print("  \"h2\" : \"%s\"," % (os.getenv('HTTP2', '')))
print("  \"h2push\" : \"%s\"," % (os.getenv('H2PUSH', '')))
print("  \"h2_stream_id\" : \"%s\"" % (os.getenv('H2_STREAM_ID', '')))
print("}")

