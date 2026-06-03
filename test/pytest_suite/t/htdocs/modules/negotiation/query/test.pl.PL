
print "Content-type: text/html\n\n";

foreach my $key (keys %ENV) {
   if ($key eq "QUERY_STRING") {
   	print "$key --> $ENV{$key}\n";
   }
}
