#!/usr/bin/env python3
import cgi, os
import cgitb; cgitb.enable()

status = '200 Ok'

try:
    form = cgi.FieldStorage()
    input = form['name']

    # Test if the file was uploaded
    if input.value is not None:
        val = os.environ[input.value] if input.value in os.environ else ""
        print("Status: 200")
        print("""\
Content-Type: text/plain\n""")
        print("{0}={1}".format(input.value, val))

    else:
        print("Status: 400 Parameter Missing")
        print("""\
Content-Type: text/html\n
    <html><body>
    <p>No name was specified: %s</p>
    </body></html>""" % (count.value))

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



