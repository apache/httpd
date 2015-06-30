#!/usr/bin/env python
# -*- coding: utf-8 -*-
import cgi, sys, time
import cgitb; cgitb.enable()

print "Content-Type: text/html;charset=UTF-8"
print

print """\
	<!DOCTYPE html><html><head>
	<title>HTML/2.0 Test File: 009 (server time)</title></head>
	<body><h1>HTML/2.0 Test File: 009</h1>
    <p>60 seconds of server time, one by one.</p>"""

for i in range(60):
	s = time.strftime("%Y-%m-%d %H:%M:%S")
	print "<div>", s, "</div>"
	sys.stdout.flush()
	time.sleep(1)

print "<p>done.</p></body></html>"