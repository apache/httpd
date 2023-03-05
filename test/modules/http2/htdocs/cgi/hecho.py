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

status = '200 Ok'

try:

    # A nested FieldStorage instance holds the file
    name = forms['name']
    value = ''
    
    try:
        value = forms['value']
    except KeyError:
        value = os.environ.get("HTTP_"+name, "unset")
    
    # Test if a value was given
    if name:
        print("Status: 200")
        print("%s: %s" % (name, value,))
        print ("""\
Content-Type: text/plain\n""")

    else:
        print("Status: 400 Parameter Missing")
        print("""\
Content-Type: text/html\n
    <html><body>
    <p>No name and value was specified: %s %s</p>
    </body></html>""" % (name, value))

except KeyError:
    print("Status: 200 Ok")
    print("""\
Content-Type: text/html\n
    <html><body>
    Echo <form method="POST" enctype="application/x-www-form-urlencoded">
    <input type="text" name="name">
    <input type="text" name="value">
    <button type="submit">Echo</button></form>
    </body></html>""")
    pass


