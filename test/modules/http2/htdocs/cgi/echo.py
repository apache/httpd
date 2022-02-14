#!/usr/bin/env python3
import sys, cgi, os

status = '200 Ok'

content = ''
for line in sys.stdin:
    content += line
    
# Just echo what we get
print("Status: 200")
print(f"Request-Length: {len(content)}")
print("Content-Type: application/data\n")
sys.stdout.write(content)

