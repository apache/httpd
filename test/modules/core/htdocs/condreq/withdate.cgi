#!/usr/bin/env python3
# A CGI script which sends a Last-Modified header in the past.

import sys

# Disable Python's platform newline translation: on Windows it would turn
# the bare "\n" below into "\r\n" in the response body.
sys.stdout.reconfigure(newline="")

sys.stdout.write("Content-Type: text/plain\r\n")
sys.stdout.write("Last-Modified: Thu, 01 Jan 2015 00:00:00 GMT\r\n\r\n")
sys.stdout.write("hi\n")
