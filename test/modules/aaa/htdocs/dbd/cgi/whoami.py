#!/usr/bin/env python3
import os

print("Content-Type: text/plain\n")
print(f"user={os.environ.get('REMOTE_USER', '')}")
print(f"role={os.environ.get('AUTHENTICATE_ROLE', '')}")
print(f"role_set={'AUTHENTICATE_ROLE' in os.environ}")
