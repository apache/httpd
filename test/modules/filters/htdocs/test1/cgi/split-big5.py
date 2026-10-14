#!/usr/bin/env python3
# A Big5 page written so that every read mod_xml2enc gets from the script
# ends with half a character, which it has to carry over to the next one.
# The pauses keep the writes from being coalesced into one read.
import sys
import time

out = sys.stdout.buffer
out.write(b"Content-Type: text/html; charset=Big5\r\n\r\n")
out.flush()
time.sleep(0.1)
for i in range(4):
    chunk = (b"<html><body>" if i == 0 else b"\xa4") + b"a" * 7998 + b"\xa4"
    out.write(chunk[:8000])
    out.flush()
    time.sleep(0.1)
out.write(b"\xa4</body></html>\n")
out.flush()
