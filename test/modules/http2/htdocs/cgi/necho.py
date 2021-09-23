#!/usr/bin/env python3
import cgi, os
import time
import cgitb; cgitb.enable()

status = '200 Ok'

try:
    form = cgi.FieldStorage()
    count = form['count']
    text = form['text']
    
    waitsec = float(form['wait1'].value) if 'wait1' in form else 0.0
    if waitsec > 0:
        time.sleep(waitsec)
    
    if int(count.value):
        print("Status: 200")
        print("""\
Content-Type: text/plain\n""")

        waitsec = float(form['wait2'].value) if 'wait2' in form else 0.0
        if waitsec > 0:
            time.sleep(waitsec)
    
        i = 0;
        for i in range(0, int(count.value)):
            print("%s" % (text.value))

        waitsec = float(form['wait3'].value) if 'wait3' in form else 0.0
        if waitsec > 0:
            time.sleep(waitsec)
    
    else:
        print("Status: 400 Parameter Missing")
        print("""\
Content-Type: text/html\n
    <html><body>
    <p>No count was specified: %s</p>
    </body></html>""" % (count.value))

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


