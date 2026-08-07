
# numbers.pl
# program rewrite map for mod_rewrite testing
#
$|=1;
my %map = (	1	=>	'one',
		2	=>	'two',
		3	=>	'three',
		4	=>	'four',
		5	=>	'five',
		6	=>	'six'	);

while (<STDIN>) {
	chomp;

	print STDERR "GOT: ->$_<-\n";
	my $m = $map{$_};
	print STDERR "MAPPED: ->$_<-\n";

	if ($m) {
		print STDOUT "$m\n";
	} else {
		print STDOUT "NULL";
	}
}
close (LOG);
