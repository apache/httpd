#!/usr/bin/env python3
# A CGI script which sends an invalid Last-Modified header, which httpd
# ignores, so the response has no modification date.

import sys

# Disable Python's platform newline translation: on Windows it would turn
# the bare "\n" below into "\r\n" in the response body.
sys.stdout.reconfigure(newline="")

sys.stdout.write("Content-Type: text/plain\r\n")
sys.stdout.write("Last-Modified: not a date\r\n\r\n")
sys.stdout.write("hi\n")
