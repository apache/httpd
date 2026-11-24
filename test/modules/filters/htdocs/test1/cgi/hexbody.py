#!/usr/bin/env python3
# Print the request body in hex, so a test of an input filter which
# translates the body sees its bytes whatever is done to the response.
import sys

body = sys.stdin.buffer.read()
print("Content-Type: application/octet-stream")
print()
print(body.hex())
