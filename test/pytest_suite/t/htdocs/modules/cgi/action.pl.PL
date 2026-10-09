use strict;

print "Content-type: text/plain\n\n";

print $ENV{PATH_INFO} . "\n";

if (my $ct = $ENV{CONTENT_LENGTH}) {
    read STDIN, my $buffer, $ct;
    print $buffer;
}
