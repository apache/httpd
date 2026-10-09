print "HTTP/1.1 200 OK\r\n";
print "Transfer-Encoding: chunked\r\n";
print "\r\n";

$| = 1;

sub dripfeed {
    my $s = shift;

    while (length($s)) {
        select(undef, undef, undef, 0.2);
        print substr($s, 0, 1);
        $s = substr($s, 1);
    }
}

dripfeed "0005\r\nabcde\r\n1; foo=bar\r\nf\r\n0\r\n\r\n";
