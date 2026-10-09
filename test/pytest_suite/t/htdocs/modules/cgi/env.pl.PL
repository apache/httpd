use strict;

print "Content-type: text/plain\n\n";

for (sort keys %ENV) {
    print "$_ = $ENV{$_}\n";
}
