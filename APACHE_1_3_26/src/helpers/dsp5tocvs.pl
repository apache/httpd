use IO::File;
use File::Find;

chdir '..';
find(\&tovc6, '.');

sub tovc6 { 

    if (m|.dsp$|) {
        $oname = $_;
	$tname = '.#' . $_;
	$verchg = 0;
	$srcfl = new IO::File $_, "r" || die;
	$dstfl = new IO::File $tname, "w" || die;
	while ($src = <$srcfl>) {
	    if ($src =~ s|Format Version 5\.00|Format Version 6\.00|) {
		$verchg = -1;
	    }
	    if ($src =~ s|^(!MESSAGE .*)\\\n|$1|) {
		$cont = <$srcfl>;
		$src = $src . $cont;
		$verchg = -1;
	    }
            print $dstfl $src; 
	    if ($verchg && $src =~ m|^# Begin Project|) {
		print $dstfl "# PROP AllowPerConfigDependencies 0\n"; 
	    }
	}
	undef $srcfl;
	undef $dstfl;
	if ($verchg) {
	    unlink $oname || die;
	    rename $tname, $oname || die;
	    print "Converted VC5 project " . $oname . " to VC6 in " . $File::Find::dir . "\n"; 
	}
	else {
	    unlink $tname;
	}
    }
}
