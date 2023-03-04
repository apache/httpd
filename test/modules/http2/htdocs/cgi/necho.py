#!/usr/bin/env python3
import time
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


