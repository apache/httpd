#
# fixwin32mak.pl ::: Apache/Win32 maintanace program
#
# This program, launched from the build/ directory, replaces all nasty absoulute paths
# in the win32 .mak files with the appropriate relative root.
#
# Run this program prior to committing or packaging any newly exported make files.

use Cwd;
use IO::File;
use File::Find;

chdir '..';
$root = cwd;
$root =~ s|.:(.*)|cd "$1|;
$root =~ s|/|\\\\|g;
find(\&fixcwd, '.');

sub fixcwd { 
    if (m|.mak$|) {
	$repl = $File::Find::dir;
        $repl =~ s|^./||;
        $repl =~ s|[^\./]+|..|g;
        $repl =~ s|/|\\|;
        $oname = $_;
	$tname = '.#' . $_;
	$verchg = 0;
	$srcfl = new IO::File $_, "r" || die;
	$dstfl = new IO::File $tname, "w" || die;
	while ($src = <$srcfl>) {
	    if ($src =~ s|^(\s*)$root|$1cd "$repl|) {
		$verchg = -1;
	    }
            print $dstfl $src; 
	}
	undef $srcfl;
	undef $dstfl;
	if ($verchg) {
	    unlink $oname || die;
	    rename $tname, $oname || die;
	    print "Corrected absolute paths within " . $oname . " in " . $File::Find::dir . "\n"; 
	}
	else {
	    unlink $tname;
	}
    }
}
