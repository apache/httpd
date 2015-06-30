#!/usr/bin/env python
import cgi, os
import cgitb; cgitb.enable()

status = '200 Ok'

try:
    form = cgi.FieldStorage()
    
    # A nested FieldStorage instance holds the file
    count = form['count']
    text = form['text']
    
    # Test if the file was uploaded
    if int(count.value):
        print "Status: 200"
        print """\
Content-Type: text/plain\n"""
        i = 0;
        for i in range(0, int(count.value)):
            print """%s""" % (text.value,)

    else:
        print "Status: 400 Parameter Missing"
        print """\
    Content-Type: text/html\n
    <html><body>
    <p>No count was specified: %s</p>
    </body></html>""" % (count.value,)

except KeyError:
    print "Status: 200 Ok"
    print """\
    Content-Type: text/html\n
    <html><body>
    Echo <form method="POST" enctype="application/x-www-form-urlencoded">
    <input type="text" name="count">
    <input type="text" name="text">
    <button type="submit">Echo</button></form>
    </body></html>"""
    pass

