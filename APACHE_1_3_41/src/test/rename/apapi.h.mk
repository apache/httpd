:
eval 'exec perl -S $0 ${1+"$@"}'
    if $running_under_some_shell;
##
##  apapi.h.mk -- 
##

#   configuration
$id       = "../src/ID";
$renamecf = "./rename.cf";
$header   = "./apapi.h";

sub func_prototype {
    my ($func) = @_;

    $rc = join('', `lid -f $id --key=token --result=grep $func`);
    if (   $rc =~ m|^(.+?\.h):\d+:\s*API_EXPORT(?:_NONSTD)?\(.+?\)\s*$func\s*\(|m
        or $rc =~ m|^(.+?\.h):\d+:\s*(?:extern\s*)?API_VAR_EXPORT\s*.+?$func.+?;|m) {
		$file = $1;
		open(FP, "<$file") || die;
		$contents = join('', <FP>);
		close(FP);
        if (($r, $f) = ($contents =~ m|\n\s*API_EXPORT(?:_NONSTD)?\(([^)]+)\)\s+($func\s*\(.+?\);)|s)) {
            $r =~ s|\s*\n\s*| |sg;
            $r =~ s|\s+| |sg;
			$r =~ s|extern\s+||g;
            $f =~ s|\s*\n\s*| |sg;
            $f =~ s|\s+| |sg;
            $pt = sprintf("%-20s %s", $r, $f);
            return $pt;
        }
        if (($r, $f) = ($contents =~ m|\n\s*(?:extern\s*)?API_VAR_EXPORT\s*([^;]*?)($func[^;]*;)|s)) {
            $r =~ s|\s*\n\s*| |sg;
            $r =~ s|\s+| |sg;
			$r =~ s|extern\s+||g;
            $f =~ s|\s*\n\s*| |sg;
            $f =~ s|\s+| |sg;
            $pt = sprintf("%-20s %s", $r, $f);
            return $pt;
        }
	}
    return '';
}

open(CFG, "<$renamecf") || die;
open(HDR, ">$header") || die;
print HDR <<'EOT';
/*
**  apapi.h -- Apache 1.3 API prototypes
**
**  THIS IS A COMPLETE LIST OF PROTOTYPES
**  FOR ALL PUBLIC API FUNCTIONS
*/

#ifndef APAPI_H
#define APAPI_H

EOT
while ($l = <CFG>) {
    $l =~ s|\n$||;
    next if ($l =~ m|^\s*#.*| or $l =~ m|^\s*$|);
    if (($s1, $old, $s2, $new, $s3) = ($l =~ m|^(\s*)(\S+)(\s+)(\S+)(\s*)$|)) {
        if ($new =~ m|^API_|) {
            $new =~ s|^API_|ap_|;
			$pt = &func_prototype($new);
            if ($pt eq '') {
                print STDERR "Sorry, prototype for `$new' cannot be determined automatically\n";
                print HDR "/* prototype for `$new' cannot be automatically determined */\n";
            }
            else {
                print HDR "extern $pt\n";
            }
        }
    }
}
print HDR <<'EOT';

#endif /* APAPI_H */
EOT
close(CFG);
close(HDR);

