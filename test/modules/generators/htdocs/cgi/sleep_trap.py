#!/usr/bin/env python3
import signal
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(10)
print("Content-Type: text/plain\n")
print("too late")
