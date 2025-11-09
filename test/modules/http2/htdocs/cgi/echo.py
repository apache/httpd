#!/usr/bin/env python3
import os, sys
import multipart

status = '200 Ok'

content = ''
for line in sys.stdin:
    content += line
    
# Just echo what we get
print("Status: 200")
print(f"Request-Length: {len(content)}")
print("Content-Type: application/data\n")
sys.stdout.write(content)

