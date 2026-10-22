#!/usr/bin/env python3
# A CGI script which sends a Last-Modified header in the past.

import sys

sys.stdout.write("Content-Type: text/plain\r\n")
sys.stdout.write("Last-Modified: Thu, 01 Jan 2015 00:00:00 GMT\r\n\r\n")
sys.stdout.write("hi\n")
