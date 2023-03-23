#!/usr/bin/env python3
import os

def get_var(name: str, def_val: str = ""):
    if name in os.environ:
        return os.environ[name]
    return def_val

print("Content-Type: application/json")
print()
print("""{{ "https" : "{https}",
  "host" : "{server_name}",
  "protocol" : "{protocol}",
  "ssl_protocol" : "{ssl_protocol}",
  "ssl_cipher" : "{ssl_cipher}"
}}""".format(
    https=get_var('HTTPS', ''),
    server_name=get_var('SERVER_NAME', ''),
    protocol=get_var('SERVER_PROTOCOL', ''),
    ssl_protocol=get_var('SSL_PROTOCOL', ''),
    ssl_cipher=get_var('SSL_CIPHER', ''),
))

