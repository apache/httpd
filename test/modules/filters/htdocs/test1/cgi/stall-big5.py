#!/usr/bin/env python3
# A Big5 page whose first 8000 bytes (one read from the script) end with
# half a character, a little more, then nothing for longer than the script
# timeout.
import sys
import time

out = sys.stdout.buffer
out.write(b"Content-Type: text/html; charset=Big5\r\n\r\n")
out.flush()
time.sleep(0.2)
out.write(b"<html><body>" + b"a" * 7987 + b"\xa4")
out.flush()
time.sleep(0.2)
out.write(b"\xa4" + b"b" * 299)
out.flush()
time.sleep(5)
out.write(b"</body></html>\n")
