#!/usr/bin/env python3
import time
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
status = '200 Ok'

try:
    count = forms['count']
    text = forms['text']
    
    waitsec = float(forms['wait1']) if 'wait1' in forms else 0.0
    if waitsec > 0:
        time.sleep(waitsec)
    
    if int(count):
        print("Status: 200")
        print("""\
Content-Type: text/plain\n""")

        waitsec = float(forms['wait2']) if 'wait2' in forms else 0.0
        if waitsec > 0:
            time.sleep(waitsec)
    
        i = 0;
        for i in range(0, int(count)):
            print("%s" % (text))

        waitsec = float(forms['wait3']) if 'wait3' in forms else 0.0
        if waitsec > 0:
            time.sleep(waitsec)
    
    else:
        print("Status: 400 Parameter Missing")
        print("""\
Content-Type: text/html\n
    <html><body>
    <p>No count was specified: %s</p>
    </body></html>""" % (count))

except KeyError:
    print("Status: 200 Ok")
    print("""\
Content-Type: text/html\n
    <html><body>
    Echo <form method="POST" enctype="application/x-www-form-urlencoded">
    <input type="text" name="count">
    <input type="text" name="text">
    <button type="submit">Echo</button></form>
    </body></html>""")
    pass


