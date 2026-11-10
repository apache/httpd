#!/usr/bin/env python3
import json
import os
import sys

body = json.dumps(dict(os.environ)).encode()
sys.stdout.buffer.write(b"Content-Type: application/json\r\n\r\n" + body)
