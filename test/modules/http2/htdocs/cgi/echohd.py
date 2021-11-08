#!/usr/bin/env python3
import cgi, os
import cgitb; cgitb.enable()

status = '200 Ok'

form = cgi.FieldStorage()
name = form.getvalue('name')

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


