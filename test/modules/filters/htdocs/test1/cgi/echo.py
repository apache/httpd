#!/usr/bin/env python3
# Echo the request body back verbatim, so an InputSed test can see exactly
# what the input filter handed to the handler.  Read to EOF rather than
# CONTENT_LENGTH bytes: mod_sed rewrites the body but not the header, so the
# two need not agree.
import sys

body = sys.stdin.buffer.read()
print("Content-Type: text/plain")
print()
sys.stdout.flush()
sys.stdout.buffer.write(body)
