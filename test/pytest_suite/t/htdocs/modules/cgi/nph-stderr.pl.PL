# produces lots of stderr output

print "HTTP/1.0 200 OK\r\n";

print STDERR 'x'x8192;
print "Content-Type: text/plain\r\n\r\n";

print "this is nph-stdout";

close STDOUT;

print STDERR "this is nph-stderr";
