#!/usr/bin/env python
# -*- coding: utf-8 -*-
import cgi, sys
import cgitb; cgitb.enable()

print "Content-Type: text/html;charset=UTF-8"
print

print """\
	<!DOCTYPE html><html><head>
	<title>HTML/2.0 Test File: 007 (received data)</title></head>
	<body><h1>HTML/2.0 Test File: 007</h1>"""

# alternative output: parsed form params <-> plain POST body
parseContent = True		# <-> False

if parseContent:
	print '<h2>Data processed:</h2><ul>'
	form = cgi.FieldStorage()
	for name in form:
		print '<li>', name, ': ', form[name].value, '</li>'
	print '</ul>'
else:
	print '<h2>POST data output:</h2><div><pre>'
	data = sys.stdin.read()
	print data
	print '</pre></div>'
	
print '</body></html>'