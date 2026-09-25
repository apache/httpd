#!/usr/bin/env python3
import sys

print("Content-Type: text/plain\n")
for arg in sys.argv[1:]:
    print(arg)
