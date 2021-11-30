#!/usr/bin/env python3
import json
import os, cgi
import re

jenc = json.JSONEncoder()

def get_var(name: str, def_val: str = ""):
    if name in os.environ:
        return os.environ[name]
    return def_val

def get_json_var(name: str, def_val: str = ""):
    var = get_var(name, def_val=def_val)
    return jenc.encode(var)


name = None
try:
    form = cgi.FieldStorage()
    if 'name' in form:
        name = str(form['name'].value)
except Exception:
    pass

print("Content-Type: application/json\n")
if name:
    print(f"""{{ "{name}" : {get_json_var(name, '')}}}""")
else:
    print(f"""{{ "https" : {get_json_var('HTTPS', '')},
  "host" : {get_json_var('SERVER_NAME', '')},
  "protocol" : {get_json_var('SERVER_PROTOCOL', '')},
  "ssl_protocol" : {get_json_var('SSL_PROTOCOL', '')},
  "ssl_cipher" : {get_json_var('SSL_CIPHER', '')}
}}""")

