:
eval 'exec perl -S $0 ${1+"$@"}'
    if $running_under_some_shell;
##
##  rename -- global symbol renaming for C sources
##  Written by Ralf S. Engelschall <rse@apache.org>
##

#   configuration
$config = "./rename.cf";
$csubst = "./csubst/csubst";

#   parameter
@SRC = @ARGV;

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

#   create csubst command line
$csubst_cmd = "$csubst";
foreach $old (keys(%SUBST)) {
    $new = $SUBST{$old};
    $csubst_cmd .= " -s $old:$new";
}

#   create file list
@FILES = ();
foreach $src (@SRC) {
    if (-f $src) {
        push(@FILES, $src);
    }
    else {
        push(@FILES, `find $src -name "*.[ch]" -type f -print`);
    }
}

#   walk through the file list
foreach $file (@FILES) {
    $file =~ s|\n$||;
    print STDERR " FILE $file\n";
    open(PIPE, "cp $file $file.bak && " .
               "$csubst_cmd -o $file.n $file && " .
               "cp $file.n $file && " .
               "rm $file.n " .
               "|") || die;
    %stat = ();
    while (<PIPE>) {
        if (m|^Subst:\s+(\S+)\s+->\s+\S+|) {
            $stat{$1} = 0 if (not defined $stat{$1});
            $stat{$1}++;
        }
    }
    close(PIPE);
    @S = sort(keys(%stat));
    $n = -1;
    if ($#S == -1) {
        print STDERR " --NO-SYMBOL-SUBSTITUTIONS--\n";
    }
    else {
        foreach $s (@S) {
            printf(STDERR " %-25s", "$s:$stat{$s}");
            $n++;
            if ($n % 3 == 0) {
                print STDERR "\n";
            }
        }
        if ($n % 3 != 0) {
            print STDERR "\n";
        }
    }
    print STDERR "\n";
}

