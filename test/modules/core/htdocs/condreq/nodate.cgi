#!/usr/bin/env python3
# A CGI script which has no modification date, no Last-Modified header.

import sys

# Disable Python's platform newline translation: on Windows it would turn
# the bare "\n" below into "\r\n" in the response body.
sys.stdout.reconfigure(newline="")

sys.stdout.write("Content-Type: text/plain\r\n\r\n")
sys.stdout.write("hi\n")
