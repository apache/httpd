use IO::File;
use File::Find;

chdir '..';
find(\&tovc5, '.');

sub tovc5 { 

    if (m|.dsp$|) {
	$tname = '.#' . $_;
	print "Convert project " . $_ . " to CVS standard VC5 in " . $File::Find::dir . "\n"; 
	$srcfl = new IO::File $_, "r" || die;
	$dstfl = new IO::File $tname, "w" || die;
	while ($src = <$srcfl>) {
	    $src =~ s|Format Version 6\.00|Format Version 5\.00|;
#           This is BUCK UGLY... and I know there is a way to do it right... would someone fix?
	    $src =~ s|^(# ADD CPP .*)/ZI (.*)|$1/Zi $2|;
	    $src =~ s|^(# ADD BASE CPP .*)/ZI (.*)|$1/Zi $2|;
	    if ($src !~ m|^# PROP AllowPerConfigDependencies|) {
		print $dstfl $src; }
	}
	undef $srcfl;
	undef $dstfl;
	unlink $_;
	rename $tname, $_;
    }
}