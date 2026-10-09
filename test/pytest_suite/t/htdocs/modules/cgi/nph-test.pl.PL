print "HTTP/1.0 200 OK\r\n";
print join("\n",
     'Content-type: text/html',
     'Pragma: no-cache',
     'Cache-control: must-revalidate, no-cache, no-store',
     'Expires: -1',
     "\n");

print "ok\n";
