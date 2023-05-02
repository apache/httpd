#!/usr/bin/env python3
import os, sys
from requestparser import get_request_params


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


