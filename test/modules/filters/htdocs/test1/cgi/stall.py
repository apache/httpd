#!/usr/bin/env python3
# The start of a page, then nothing for longer than the script timeout, so
# the output filters see a body whose read fails part way through.
import sys
import time

print("Content-Type: text/html")
print()
print("<html><body>stalled", end="")
sys.stdout.flush()
time.sleep(5)
print("</body></html>")
