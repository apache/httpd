#!/usr/bin/env python3
# A CGI script which has no modification date, no Last-Modified header.

import sys

sys.stdout.write("Content-Type: text/plain\r\n\r\n")
sys.stdout.write("hi\n")
