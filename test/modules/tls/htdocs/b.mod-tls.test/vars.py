#!/usr/bin/env python3
import json
import os, sys
import multipart
from urllib import parse


def get_request_params():
    oforms = {}
    if "REQUEST_URI" in os.environ:
        qforms = parse.parse_qs(parse.urlsplit(os.environ["REQUEST_URI"]).query)
        for name, values in qforms.items():
            oforms[name] = values[0]
    myenv = os.environ.copy()
    myenv['wsgi.input'] = sys.stdin.buffer
    mforms, ofiles = multipart.parse_form_data(environ=myenv)
    for name, item in mforms.items():
        oforms[name] = item
    return oforms, ofiles


forms, files = get_request_params()

jenc = json.JSONEncoder()

def get_var(name: str, def_val: str = ""):
    if name in os.environ:
        return os.environ[name]
    return def_val

def get_json_var(name: str, def_val: str = ""):
    var = get_var(name, def_val=def_val)
    return jenc.encode(var)


name = forms['name'] if 'name' in forms else None

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

