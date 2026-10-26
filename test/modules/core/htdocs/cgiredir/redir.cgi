#!/usr/bin/env python3
# A CGI script which performs an RFC 3875 "local redirect" to the path
# given in the query string.

import os
import sys

query = os.environ.get("QUERY_STRING", "")
if query:
    sys.stdout.write("Location: {0}\r\n\r\n".format(query))
else:
    sys.stdout.write("Content-Type: text/plain\r\n\r\n")
    sys.stdout.write("usage: redir.cgi?/local/path\n")
