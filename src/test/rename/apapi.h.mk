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
    if (($r, $f) = ($rc =~ m|\.c:\d+:\s*API_EXPORT\((.+?)\)(.+?\))|s)) {
        $pt = "$r$f";
        $pt =~ s|\n.+?:\d+:||sg;
        return "extern $1$2;";
    }
    return '';
}

open(CFG, "<$renamecf") || die;
open(HDR, ">$header") || die;
print HDR <<'EOT';
/*
**  apapi.h -- Apache API prototypes
**
**  THIS IS NOT COMPLETE BECAUSE IT NEEDS MANUAL FIXUP!
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
            if ($pt eq '') {
                print STDERR "Sorry, prototype for `$new' cannot be determined automatically\n";
                print HDR "/* prototype for `$new' cannot be automatically determined */\n";
            }
            elsif ($pt eq 'extern ;') {
                print STDERR "Sorry, prototype for `$new' cannot be determined automatically\n";
                print HDR "/* prototype for `$new' cannot be automatically determined */\n";
            }
            else {
                print HDR "$pt\n";
            }
        }
    }
}
print HDR <<'EOT';

#endif /* APAPI_H */
EOT
close(CFG);
close(HDR);

