use IO::File;
use File::Find;

chdir '..';
find(\&tovc5, '.');

sub tovc5 { 

    if (m|.dsp$|) {
	$tname = '.#' . $_;
        $verchg = 0;
	$srcfl = new IO::File $_, "r" || die;
	$dstfl = new IO::File $tname, "w" || die;
	while ($src = <$srcfl>) {
	    if ($src =~ s|Format Version 6\.00|Format Version 5\.00|) {
		$verchg = -1;
	    }
	    if ($src =~ s|^(# ADD CPP .*)/ZI (.*)|$1/Zi $2|) {
		$verchg = -1;
	    }
	    if ($src =~ s|^(# ADD BASE CPP .*)/ZI (.*)|$1/Zi $2|) {
		$verchg = -1;
	    }
	    if ($src !~ m|^# PROP AllowPerConfigDependencies|) {
		print $dstfl $src; }
	    else {
		$verchg = -1;

	    }
	}
	undef $srcfl;
	undef $dstfl;
	if ($verchg) {
	    unlink $_;
	    rename $tname, $_;
	    print "Converted VC6 project " . $_ . " to VC5 in " . $File::Find::dir . "\n"; 
	}
	else {
	    unlink $tname;
	}
    }
}