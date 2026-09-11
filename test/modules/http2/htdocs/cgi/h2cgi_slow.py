#!/usr/bin/env python3
# Start a response (status + headers + a little body), then go silent for
# longer than the server's `Timeout`. Over HTTP/2 this makes Apache's content
# filter time out reading from the CGI (AH01220): the response was started but
# never completed (no EOS). A correct server RST_STREAMs the stream; a buggy
# one leaves the client hanging. Used by test_105_timeout.py.
import sys
import time

sys.stdout.write("Content-Type: application/octet-stream\r\n\r\n")
sys.stdout.write("X" * 16384)
sys.stdout.flush()
time.sleep(30)
