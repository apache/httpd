#!/usr/bin/env python

import os

print "Content-Type: text/html"
print
print """\
<html>
<body>
<h2>Hello World!</h2>"""
print "SSL_PROTOCOL=" + os.getenv('SSL_PROTOCOL', '')
print """</body>
</html>"""