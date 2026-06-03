# closes stderr during script execution

print "Content-Type: text/plain\n\n";
print "this is more stdout";

close STDOUT;

print STDERR "this is a post-stdout-closure error message";
