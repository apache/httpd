#!/usr/bin/env python3
import cgi, os
import cgitb; cgitb.enable()

status = '200 Ok'

try:
    form = cgi.FieldStorage()
    
    # A nested FieldStorage instance holds the file
    name = form['name'].value
    value = ''
    
    try:
        value = form['value'].value
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


