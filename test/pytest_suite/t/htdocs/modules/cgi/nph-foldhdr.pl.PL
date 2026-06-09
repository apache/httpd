# produces output with folded response headers

print "HTTP/1.0 200 OK\r\n";

for (1..50) {
    print "X-Foo-Bar-$_:\n " . 'x'x($_*10) . "\n";
    print "X-Bar-$_:\n gamm\r\n beta\n theta\r\n";
}

print "Content-type: \n  text/plain\n\n";

print "hello, world";
