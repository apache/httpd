#echo some data back to the client

print "Content-type: text/plain\n\n";

if (my $ct = $ENV{CONTENT_LENGTH}) {
    read STDIN, my $buffer, $ct;
    print $buffer;
}
elsif (my $qs = $ENV{QUERY_STRING}) {
    print $qs;
}
else {
    print "nada";
}
