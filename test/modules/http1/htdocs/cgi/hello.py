#!/usr/bin/env python3

import os

print("Content-Type: application/json")
print()
print("{")
print("  \"https\" : \"%s\"," % (os.getenv('HTTPS', '')))
print("  \"host\" : \"%s\"," % (os.getenv('SERVER_NAME', '')))
print("  \"protocol\" : \"%s\"," % (os.getenv('SERVER_PROTOCOL', '')))
print("  \"ssl_protocol\" : \"%s\"," % (os.getenv('SSL_PROTOCOL', '')))
print("  \"h2\" : \"%s\"," % (os.getenv('HTTP2', '')))
print("  \"h2push\" : \"%s\"" % (os.getenv('H2PUSH', '')))
print("}")

