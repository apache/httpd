#!/usr/bin/env python3
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


