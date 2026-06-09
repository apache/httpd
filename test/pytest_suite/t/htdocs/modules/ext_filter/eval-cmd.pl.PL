use strict;

$| = 1;

my $cmd = shift;
do {eval $cmd; print } while <>;
