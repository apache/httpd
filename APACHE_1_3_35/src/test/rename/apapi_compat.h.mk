:
eval 'exec perl -S $0 ${1+"$@"}'
    if $running_under_some_shell;
##
##  apapi_compat.h.mk 
##

#   configuration
$config = "./rename.cf";
$header = "./apapi_compat.h";

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
**  apapi_compat.h -- Apache API symbol space
**                    backward compatibility defines
**
**  INCLUDE THIS HEADER FILE ONLY IF YOU REALLY NEED
**  BACKWARD COMPATIBILITY FOR USED API SYMBOLS.
*/

#ifndef APAPI_COMPAT_H
#define APAPI_COMPAT_H

/* 
 *   Mapping of Apache 1.2 symbols to 
 *   official Apache 1.3 API symbols
 */

EOT
$apapiprefix = $PREFIX{'API_'};
foreach $s (sort(keys(%SUBST))) {
    $n = $SUBST{$s};
    next if ($n !~ m|^$apapiprefix|);
    printf(FP "#define %-30s %s\n", $s, $n);
}
print FP <<'EOT';

/* 
 *   Mapping of symbols which are private
 *   to Apache httpd and should not be considered 
 *   part of the public API
 */

#ifdef APAPI_STRICT

EOT
foreach $s (sort(keys(%SUBST))) {
    $n = $SUBST{$s};
    next if ($n =~ m|^$apapiprefix|);
    printf(FP "#define %-30s %s\n", $s, "DO_NOT_USE_$s");
}
print FP <<'EOT';

#else /* APAPI_STRICT */

EOT
foreach $s (sort(keys(%SUBST))) {
    $n = $SUBST{$s};
    next if ($n =~ m|^$apapiprefix|);
    printf(FP "#define %-30s %s\n", $s, $n);
}
print FP <<'EOT';

#endif /* APAPI_STRICT */

#endif /* APAPI_COMPAT_H */
EOT
close(FP);

