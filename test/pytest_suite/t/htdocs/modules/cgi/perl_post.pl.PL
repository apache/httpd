local ($buffer, @pairs, $pair, $name, $value);

print "Content-type: text/plain\n\n";

$ENV{'REQUEST_METHOD'} =~ tr/a-z/A-Z/;
print "$ENV{'REQUEST_METHOD'}\n";

# Read in text
if ($ENV{'REQUEST_METHOD'} eq "POST") {
    read(STDIN, $buffer, $ENV{'CONTENT_LENGTH'});
} else {
    $buffer = $ENV{'QUERY_STRING'};
}

# Split information into name/value pairs
@pairs = split(/&/, $buffer);
foreach $pair (@pairs) {
    ($name, $value) = split(/=/, $pair);
    $value =~ tr/+/ /;
    $value =~ s/%(..)/pack("C", hex($1))/eg;

    print "$name: $value\n";
}
