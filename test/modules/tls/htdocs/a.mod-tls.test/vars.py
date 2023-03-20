#!/usr/bin/env python3
import json
import os, sys
from urllib import parse
import multipart # https://github.com/andrew-d/python-multipart (`apt install python3-multipart`)


def get_request_params():
    oforms = {}
    ofiles = {}
    if "REQUEST_URI" in os.environ:
        qforms = parse.parse_qs(parse.urlsplit(os.environ["REQUEST_URI"]).query)
        for name, values in qforms.items():
            oforms[name] = values[0]
    if "HTTP_CONTENT_TYPE" in os.environ:
        ctype = os.environ["HTTP_CONTENT_TYPE"]
        if ctype == "application/x-www-form-urlencoded":
            qforms = parse.parse_qs(parse.urlsplit(sys.stdin.read()).query)
            for name, values in qforms.items():
                oforms[name] = values[0]
        elif ctype.startswith("multipart/"):
            def on_field(field):
                oforms[field.field_name] = field.value
            def on_file(file):
                ofiles[field.field_name] = field.value
            multipart.parse_form(headers={"Content-Type": ctype}, input_stream=sys.stdin.buffer, on_field=on_field, on_file=on_file)
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

