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
name = forms['name'] if 'name' in forms else None

if name:
    print("Status: 200")
    print("""\
Content-Type: text/plain\n""")
    print("""%s: %s""" % (name, os.environ['HTTP_'+name]))
else:
    print("Status: 400 Parameter Missing")
    print("""\
Content-Type: text/html\n
<html><body>
<p>No name was specified</p>
</body></html>""")


