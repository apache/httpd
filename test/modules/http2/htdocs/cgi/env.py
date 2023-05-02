#!/usr/bin/env python3
import os, sys
from requestparser import get_request_params


forms, files = get_request_params()

status = '200 Ok'

try:
    ename = forms['name']

    # Test if the file was uploaded
    if ename is not None:
        val = os.environ[ename] if ename in os.environ else ""
        print("Status: 200")
        print("""\
Content-Type: text/plain\n""")
        print(f"{ename}={val}")

    else:
        print("Status: 400 Parameter Missing")
        print("""\
Content-Type: text/html\n
    <html><body>
    <p>No name was specified: name</p>
    </body></html>""")

except KeyError:
    print("Status: 200 Ok")
    print("""\
Content-Type: text/html\n
    <html><body>
    Echo <form method="POST" enctype="application/x-www-form-urlencoded">
    <input type="text" name="name">
    <button type="submit">submit</button></form>
    </body></html>""")
    pass



