#!/usr/bin/env python3
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
text = forms['text'] if 'text' in forms else "a"
count = int(forms['count']) if 'count' in forms else 77784

print("Status: 200 OK")
print("Content-Type: text/html")
print()
sys.stdout.flush()
for _ in range(count):
    sys.stdout.write(text)

