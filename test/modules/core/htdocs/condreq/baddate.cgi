#!/usr/bin/env python3
# A CGI script which sends an invalid Last-Modified header, which httpd
# ignores, so the response has no modification date.

import sys

sys.stdout.write("Content-Type: text/plain\r\n")
sys.stdout.write("Last-Modified: not a date\r\n\r\n")
sys.stdout.write("hi\n")
