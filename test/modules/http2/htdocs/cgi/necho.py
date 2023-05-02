#!/usr/bin/env python3
import time
import os, sys
from requestparser import get_request_params


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

except KeyError as ex:
    print("Status: 200 Ok")
    print(f"""\
Content-Type: text/html\n
    <html><body>uri: uri={os.environ['REQUEST_URI']} ct={os.environ['CONTENT_TYPE']} ex={ex}
    forms={forms}
    Echo <form method="POST" enctype="application/x-www-form-urlencoded">
    <input type="text" name="count">
    <input type="text" name="text">
    <button type="submit">Echo</button></form>
    </body></html>""")
    pass


