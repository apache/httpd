#!/usr/bin/env python3

import cgi
import cgitb; cgitb.enable()
import os
import sys

try:
    form = cgi.FieldStorage()
    count = form['count'].value
    text = form['text'].value
except KeyError:
    text="a"
    count=77784

count = int(count)

print("Status: 200 OK")
print("Content-Type: text/html")
print()
sys.stdout.flush()
for _ in range(count):
    sys.stdout.write(text)

