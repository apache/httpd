#!/usr/bin/env python3

import os

print("Content-Type: text/plain")
print("X-Replace-Session: key1=foo&key2=&key3=bar")
print()

for key, value in sorted(os.environ.items()):
    print(f"{key}={value}")
