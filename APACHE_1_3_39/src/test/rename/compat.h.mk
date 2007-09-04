:
eval 'exec perl -S $0 ${1+"$@"}'
    if $running_under_some_shell;
##
##  compat.h.mk 
##

#   configuration
$config = "./rename.cf";
$header = "./compat.h";

#   read config file into hash
%PREFIX = ();
%SUBST = ();
open(CFG, "<$config") || die;
while (<CFG>) {
    s|\n$||;
    next if (m|^\s*#.*| or m|^\s*$|);
    if (($symbolic, $real) = m|^\s*(\S+)\s*=\s*(\S+)\s*$|) {
        $PREFIX{$symbolic} = $real;
    }
    elsif (($old, $new) = m|^\s*(\S+)\s+(\S+)\s*$|) {
        foreach $p (keys(%PREFIX)) {
            $new =~ s|^$p|$PREFIX{$p}|;
        }
        $SUBST{$old} = $new;
    }
}
close(CFG);

#   create the C header file
open(FP, ">$header") || die;
print FP <<'EOT';
/*
**  compat.h -- Apache Backward Compatibility
**
**  INCLUDE THIS HEADER FILE ONLY IF YOU REALLY NEED
**  BACKWARD COMPATIBILITY TO OLD APACHE RESOURCES.
*/

#ifndef APACHE_COMPAT_H
#define APACHE_COMPAT_H

/* 
 *   Mapping of Apache 1.2 global symbols to the
 *   namespace conflict free variants used in Apache 1.3
 */

EOT
foreach $s (sort(keys(%SUBST))) {
    $n = $SUBST{$s};
    printf(FP "#define %-30s %s\n", $s, $n);
}
print FP <<'EOT';

#endif /* APACHE_COMPAT_H */
EOT
close(FP);

