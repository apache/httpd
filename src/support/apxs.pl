#!/usr/local/bin/perl
## ====================================================================
## The Apache Software License, Version 1.1
##
## Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
## reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
##
## 1. Redistributions of source code must retain the above copyright
##    notice, this list of conditions and the following disclaimer.
##
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in
##    the documentation and/or other materials provided with the
##    distribution.
##
## 3. The end-user documentation included with the redistribution,
##    if any, must include the following acknowledgment:
##       "This product includes software developed by the
##        Apache Software Foundation (http://www.apache.org/)."
##    Alternately, this acknowledgment may appear in the software itself,
##    if and wherever such third-party acknowledgments normally appear.
##
## 4. The names "Apache" and "Apache Software Foundation" must
##    not be used to endorse or promote products derived from this
##    software without prior written permission. For written
##    permission, please contact apache@apache.org.
##
## 5. Products derived from this software may not be called "Apache",
##    nor may "Apache" appear in their name, without prior written
##    permission of the Apache Software Foundation.
##
## THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
## WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
## OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
## DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
## ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
## SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
## LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
## USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
## ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
## OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
## OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
## SUCH DAMAGE.
## ====================================================================
##
## This software consists of voluntary contributions made by many
## individuals on behalf of the Apache Software Foundation.  For more
## information on the Apache Software Foundation, please see
## <http://www.apache.org/>.
##
## Portions of this software are based upon public domain software
## originally written at the National Center for Supercomputing Applications,
## University of Illinois, Urbana-Champaign.
##
##

##
##  apxs -- APache eXtenSion tool
##  Written by Ralf S. Engelschall <rse@apache.org>
##

require 5.003;
use strict;
package apxs;

##
##  Configuration
##

my $CFG_TARGET        = q(@TARGET@);            # substituted via Makefile.tmpl 
my $CFG_CC            = q(@CC@);                # substituted via Makefile.tmpl
my $CFG_CFLAGS        = q(@CFLAGS@);            # substituted via Makefile.tmpl
my $CFG_CFLAGS_SHLIB  = q(@CFLAGS_SHLIB@);      # substituted via Makefile.tmpl
my $CFG_LD_SHLIB      = q(@LD_SHLIB@);          # substituted via Makefile.tmpl
my $CFG_LDFLAGS_SHLIB = q(@LDFLAGS_MOD_SHLIB@); # substituted via Makefile.tmpl 
my $CFG_LIBS_SHLIB    = q(@LIBS_SHLIB@);        # substituted via Makefile.tmpl 
my $CFG_PREFIX        = q(@prefix@);            # substituted via APACI install
my $CFG_SBINDIR       = q(@sbindir@);           # substituted via APACI install
my $CFG_INCLUDEDIR    = q(@includedir@);        # substituted via APACI install
my $CFG_LIBEXECDIR    = q(@libexecdir@);        # substituted via APACI install
my $CFG_SYSCONFDIR    = q(@sysconfdir@);        # substituted via APACI install

##
##  Cleanup the above stuff
##
$CFG_CFLAGS =~ s|^\s+||;
$CFG_CFLAGS =~ s|\s+$||;
$CFG_CFLAGS =~ s|\s+`.+apaci`||;

##
##  parse argument line
##

#   defaults for parameters
my $opt_n = '';
my $opt_g = '';
my $opt_c = 0;
my $opt_o = '';
my @opt_D = ();
my @opt_I = ();
my @opt_L = ();
my @opt_l = ();
my @opt_W = ();
my @opt_S = ();
my $opt_e = 0;
my $opt_i = 0;
my $opt_a = 0;
my $opt_A = 0;
my $opt_q = 0;

#   default for DSO file extension 
my $dso_ext = "so";
if ($^O eq "cygwin") {
    $dso_ext = "dll";
}

#   this subroutine is derived from Perl's getopts.pl with the enhancement of
#   the "+" metacharater at the format string to allow a list to be build by
#   subsequent occurance of the same option.
sub Getopts {
    my ($argumentative, @ARGV) = @_;
    my (@args, $first, $rest, $pos);
    my ($errs) = 0;
    local ($_);
    local ($[) = 0;

    @args = split( / */, $argumentative);
    while(@ARGV && ($_ = $ARGV[0]) =~ /^-(.)(.*)/) {
        ($first, $rest) = ($1,$2);
        if ($_ =~ m|^--$|) {
            shift(@ARGV);
            last;
        }
        $pos = index($argumentative,$first);
        if ($pos >= $[) {
            if ($args[$pos+1] eq ':') {
                shift(@ARGV);
                if ($rest eq '') {
                    unless (@ARGV) {
                        print STDERR "apxs:Error: Incomplete option: $first (needs an argument)\n";
                        ++$errs;
                    }
                    $rest = shift(@ARGV);
                }
                eval "\$opt_$first = \$rest;";
            }
            elsif ($args[$pos+1] eq '+') {
                shift(@ARGV);
                if ($rest eq '') {
                    unless (@ARGV) {
                        print STDERR "apxs:Error: Incomplete option: $first (needs an argument)\n";
                        ++$errs;
                    }
                    $rest = shift(@ARGV);
                }
                eval "push(\@opt_$first, \$rest);";
            }
            else {
                eval "\$opt_$first = 1";
                if ($rest eq '') {
                    shift(@ARGV);
                }
                else {
                    $ARGV[0] = "-$rest";
                }
            }
        }
        else {
            print STDERR "apxs:Error: Unknown option: $first\n";
            ++$errs;
            if ($rest ne '') {
                $ARGV[0] = "-$rest";
            }
            else {
                shift(@ARGV);
            }
        }
    }
    return ($errs == 0, @ARGV);
}

sub usage {
    print STDERR "Usage: apxs -g [-S <var>=<val>] -n <modname>\n";
    print STDERR "       apxs -q [-S <var>=<val>] <query> ...\n";
    print STDERR "       apxs -c [-S <var>=<val>] [-o <dsofile>] [-D <name>[=<value>]]\n";
    print STDERR "               [-I <incdir>] [-L <libdir>] [-l <libname>] [-Wc,<flags>]\n";
    print STDERR "               [-Wl,<flags>] <files> ...\n";
    print STDERR "       apxs -i [-S <var>=<val>] [-a] [-A] [-n <modname>] <dsofile> ...\n";
    print STDERR "       apxs -e [-S <var>=<val>] [-a] [-A] [-n <modname>] <dsofile> ...\n";
    exit(1);
}

#   option handling
my $rc;
($rc, @ARGV) = &Getopts("qn:gco:I+D+L+l+W+S+eiaA", @ARGV);
&usage if ($rc == 0);
&usage if ($#ARGV == -1 and not $opt_g);
&usage if (not $opt_q and not ($opt_g and $opt_n) and not $opt_i and not $opt_c and not $opt_e);

#   argument handling
my @args = @ARGV;
my $name = 'unknown';
$name = $opt_n if ($opt_n ne '');

#   overriding of configuration variables
if (@opt_S) {
    my ($opt_S);
    foreach $opt_S (@opt_S) {
        if ($opt_S =~ m/^([^=]+)=(.*)$/) {
            my ($var, $val) = ($1, $2);
            my $oldval = eval "\$CFG_$var";
            unless ($var and $oldval) {
                print STDERR "apxs:Error: no config variable $var\n";
                &usage;
            }
	    $val=~s/"/\\"/g;
            eval "\$CFG_${var}=\"${val}\"";
        } else {
            print STDERR "apxs:Error: malformatted -S option\n";
            &usage;
        }       
    }
}

##
##  Initial DSO support check
##
if ($^O ne "MSWin32") {
if (not -x "$CFG_SBINDIR/$CFG_TARGET") {
    print STDERR "apxs:Error: $CFG_SBINDIR/$CFG_TARGET not found or not executable\n";
    exit(1);
}
if (not grep(/mod_so/, `$CFG_SBINDIR/$CFG_TARGET -l`)) {
    print STDERR "apxs:Error: Sorry, no DSO support for Apache available\n";
    print STDERR "apxs:Error: under your platform. Make sure the Apache\n";
    print STDERR "apxs:Error: module mod_so is compiled into your server\n";
    print STDERR "apxs:Error: binary `$CFG_SBINDIR/$CFG_TARGET'.\n";
    exit(1);
}
}

##
##  Operation
##

#   helper function for executing a list of
#   system command with return code checks
sub execute_cmds {
    my (@cmds) = @_;
    my ($cmd, $rc);

    foreach $cmd (@cmds) {
        print STDERR "$cmd\n";
        $rc = system("$cmd");
        if ($rc != 0) {
            printf(STDERR "apxs:Break: Command failed with rc=%d\n", $rc >> 8);
            exit(1);
        }
    }
}

if ($opt_g) {
    ##
    ##  SAMPLE MODULE SOURCE GENERATION
    ##

    if (-d $name) {
        print STDERR "apxs:Error: Directory `$name' already exists. Remove it first\n";
        exit(1);
    }

    my $data = join('', <DATA>);
    $data =~ s|%NAME%|$name|sg;
    $data =~ s|%TARGET%|$CFG_TARGET|sg;
    $data =~ s|%DSO_EXT%|$dso_ext|sg;

    my ($mkf, $src) = ($data =~ m|^(.+)-=#=-\n(.+)|s);

    print STDERR "Creating [DIR]  $name\n";
    system("mkdir $name");
    print STDERR "Creating [FILE] $name/Makefile\n";
    open(FP, ">${name}/Makefile") || die;
    print FP $mkf;
    close(FP);
    print STDERR "Creating [FILE] $name/mod_$name.c\n";
    open(FP, ">${name}/mod_${name}.c") || die;
    print FP $src;
    close(FP);

    exit(0);
}

if ($opt_q) {
    ##
    ##  QUERY INFORMATION 
    ##

    my $result = '';
    my $arg;
    foreach $arg (@args) {
        my $ok = 0;
        my $name;
        foreach $name (qw(
            TARGET CC CFLAGS CFLAGS_SHLIB LD_SHLIB LDFLAGS_SHLIB LIBS_SHLIB
            PREFIX SBINDIR INCLUDEDIR LIBEXECDIR SYSCONFDIR
        )) {
            if ($arg eq $name or $arg eq lc($name)) {
                my $val = eval "\$CFG_$name";
                $result .= "${val}##";
                $ok = 1;
            }
        }
        if (not $ok) {
            printf(STDERR "apxs:Error: Invalid query string `%s'\n", $arg);
            exit(1);
        }
    }
    $result =~ s|##$||;
    $result =~ s|##| |g;
    print $result;
}

if ($opt_c) {
    ##
    ##  DSO COMPILATION
    ##

    #   split files into sources and objects
    my @srcs = ();
    my @objs = ();
    my $f;
    foreach $f (@args) {
        if ($f =~ m|\.c$|) {
            push(@srcs, $f);
        }
        else {
            push(@objs, $f);
        }
    }

    #   determine output file
    my $dso_file;
    if ($opt_o eq '') {
        if ($#srcs > -1) {
            $dso_file = $srcs[0];
            $dso_file =~ s|\.[^.]+$|.$dso_ext|;
        }
        elsif ($#objs > -1) {
            $dso_file = $objs[0];
            $dso_file =~ s|\.[^.]+$|.$dso_ext|;
        }
        else {
            $dso_file = "mod_unknown.$dso_ext";
        }
    }
    else {
        $dso_file = $opt_o;
    }

    #   create compilation commands
    my @cmds = ();
    my $opt = '';
    my ($opt_Wc, $opt_I, $opt_D);
    foreach $opt_Wc (@opt_W) {
        $opt .= "$1 " if ($opt_Wc =~ m|^\s*c,(.*)$|);
    }
    foreach $opt_I (@opt_I) {
        $opt_I = '"' . $opt_I . '"' if ($opt_I =~ m|\s|);
        $opt .= "-I$opt_I ";
    }
    foreach $opt_D (@opt_D) {
        $opt .= "-D$opt_D ";
    }
    my $cflags = "$CFG_CFLAGS $CFG_CFLAGS_SHLIB";
    if ($^O eq "MSWin32") {
        my $d = $dso_file;
        $d =~ s|\.so$||;
        $d = '"' . $d . '"' if ($d =~ m|\s|);
        $opt .= "-Fd$d ";
    }
    my $s;
    foreach $s (@srcs) {
        my $o = $s;
        $s = '"' . $s . '"' if ($s =~ m|\s|);
        if ($^O ne "MSWin32") {
            $o =~ s|\.c$|.o|;
            $o =~ s|^.*/||;
            $o = '"' . $o . '"' if ($o =~ m|\s|);
            push(@cmds, "$CFG_CC $cflags -I$CFG_INCLUDEDIR $opt -c $s");
        } else {
            $o =~ s|\.c$|.obj|;
            $o =~ s|^.*/||;
            $o = '"' . $o . '"' if ($o =~ m|\s|);
            push(@cmds, "$CFG_CC $cflags -I\"$CFG_INCLUDEDIR\" $opt -c $s -Fo$o");
        }
        unshift(@objs, $o);
    }

    #   create link command
    my $cmd;
    if ($^O ne "MSWin32") {
        $cmd = "$CFG_LD_SHLIB $CFG_LDFLAGS_SHLIB -o $dso_file";
    } else {
        $cmd = "$CFG_LD_SHLIB $CFG_LDFLAGS_SHLIB -out:\"$dso_file\"";
    }
    my $o;
    foreach $o (@objs) {
        $cmd .= " $o";
    }
    $opt = '';
    my ($opt_Wl, $opt_L, $opt_l);
    foreach $opt_Wl (@opt_W) {
        if ($CFG_LD_SHLIB !~ m/gcc$/) {
            $opt .= " $1" if ($opt_Wl =~ m|^\s*l,(.*)$|);
        } else {
            $opt .= " -W$opt_Wl";
        }
    }
    foreach $opt_L (@opt_L) {
        if ($^O ne "MSWin32") {
            $opt .= " -L$opt_L";
        } else {
            $opt .= " -libpath:\"$opt_L\"";
        }
    }
    foreach $opt_l (@opt_l) {
        if ($^O ne "MSWin32") {
            $opt .= " -l$opt_l";
        } else {
            $opt .= " $opt_l";
        }
    }
    $cmd .= $opt;
    $cmd .= " $CFG_LIBS_SHLIB";
    push(@cmds, $cmd);

    #   execute the commands
    &execute_cmds(@cmds);

    #   allow one-step compilation and installation
    if ($opt_i or $opt_e) {
        @args = ($dso_file);
    }
}

if ($opt_i or $opt_e) {
    ##
    ##  DSO INSTALLATION
    ##

    #   determine installation commands
    #   and corresponding LoadModule/AddModule directives
    my @lmd = ();
    my @amd = ();
    my @cmds = ();
    my $f;
    foreach $f (@args) {
        if ($f !~ m|\.$dso_ext$|) {
            print STDERR "apxs:Error: file $f is not a DSO\n";
            exit(1);
        }
        my $t = $f;
        if ($^O ne "MSWin32") {
            $t =~ s|^.+/([^/]+)$|$1|;
            if ($opt_i) {
                push(@cmds, "cp $f $CFG_LIBEXECDIR/$t");
                push(@cmds, "chmod 755 $CFG_LIBEXECDIR/$t");
            }
        }
	else {
            $t =~ s|^.+[/\\]([^/\\]+)$|$1|;
            if ($opt_i) {
                push(@cmds, "copy \"$f\" \"$CFG_LIBEXECDIR/$t\"");
            }
        }
        
        #   determine module symbolname and filename
        my $filename = '';
        if ($name eq 'unknown') {
            $name = '';
            my $base = $f;
            $base =~ s|\.[^.]+$||;
            if (-f "$base.c") {
                open(FP, "<$base.c");
                my $content = join('', <FP>);
                close(FP);
                if ($content =~ m|.*module\s+(?:MODULE_VAR_EXPORT\s+)?([a-zA-Z0-9_]+)_module\s*=\s*.*|s) {
                    $name = "$1";
                    $filename = "$base.c";
                    $filename =~ s|^.+/||;
                    $filename =~ s|^.+\\|| if ($^O eq "MSWin32");
                }
            }
            if ($name eq '') {
                if ($base =~ m|.*mod_([a-zA-Z0-9_]+)\..+|) {
                    $name = "$1";
                    $filename = $base;
                    $filename =~ s|^.+/||;
                    $filename =~ s|^.+\\|| if ($^O eq "MSWin32");
                }
            }
            if ($name eq '') {
                print STDERR "apxs:Error: Sorry, cannot determine bootstrap symbol name.\n";
                print STDERR "apxs:Error: Please specify one with option `-n'.\n";
                exit(1);
            }
        }
        if ($filename eq '') {
            $filename = "mod_${name}.c";
        }
        my $dir = $CFG_LIBEXECDIR;
        $dir =~ s|^$CFG_PREFIX/?||;
        $dir =~ s|(.)$|$1/|;
        push(@lmd, sprintf("LoadModule %-18s %s", "${name}_module", "$dir$t"));
        push(@amd, sprintf("AddModule %s", $filename));
    }

    #   activate module via LoadModule/AddModule directive
    if ($opt_a or $opt_A) {
        my $cfgbase = "$CFG_SYSCONFDIR/$CFG_TARGET";
        if (not -f "$cfgbase.conf") {
            print STDERR "apxs:Error: Config file $cfgbase.conf not found\n";
            exit(1);
        }

        open(FP, "<$cfgbase.conf") || die;
        my $content = join('', <FP>);
        close(FP);

        if ($content !~ m|\n#?\s*LoadModule\s+|) {
            print STDERR "apxs:Error: Activation failed for custom $cfgbase.conf file.\n";
            print STDERR "apxs:Error: At least one `LoadModule' directive already has to exist.\n";
            exit(1);
        }

        my $lmd;
        my $c = '';
        $c = '#' if ($opt_A);
        foreach $lmd (@lmd) {
            my $what = $opt_A ? "preparing" : "activating";
            if ($content !~ m|\n#?\s*$lmd|) {
                # check for open <containers>, so that the new LoadModule
                # directive always appears *outside* of an <container>.

                my $before = ($content =~ m|^(.*\n)#?\s*LoadModule\s+[^\n]+\n|s)[0];

                # the '()=' trick forces list context and the scalar
                # assignment counts the number of list members (aka number
                # of matches) then
                my $cntopen = () = ($before =~ m|^\s*<[^/].*$|mg);
                my $cntclose = () = ($before =~ m|^\s*</.*$|mg);

                if ($cntopen == $cntclose) {
                    # fine. Last LoadModule is contextless.
                    $content =~ s|^(.*\n#?\s*LoadModule\s+[^\n]+\n)|$1$c$lmd\n|s;
                }
                elsif ($cntopen < $cntclose) {
                    print STDERR 'Configuration file is not valid. There are '
                                 . "sections closed before opened.\n";
                    exit(1);
                }
                else {
                    # put our cmd after the section containing the last
                    # LoadModule.
                    my $found =
                    $content =~ s!\A (               # string and capture start
                                  (?:(?:
                                    ^\s*             # start of conf line with a
                                    (?:[^<]|<[^/])   # directive which does not
                                                     # start with '</'

                                    .*(?:$)\n        # rest of the line.
                                                     # the '$' is in parentheses
                                                     # to avoid misinterpreting
                                                     # the string "$\" as
                                                     # perl variable.

                                    )*               # catch as much as possible
                                                     # of such lines. (including
                                                     # zero)

                                    ^\s*</.*(?:$)\n? # after the above, we
                                                     # expect a config line with
                                                     # a closing container (</)

                                  ) {$cntopen}       # the whole pattern (bunch
                                                     # of lines that end up with
                                                     # a closing directive) must
                                                     # be repeated $cntopen
                                                     # times. That's it.
                                                     # Simple, eh? ;-)

                                  )                  # capture end
                                 !$1$c$lmd\n!mx;

                    unless ($found) {
                        print STDERR 'Configuration file is not valid. There '
                                     . "are sections opened and not closed.\n";
                        exit(1);
                    }
                }
            } else {
                # replace already existing LoadModule line
                $content =~ s|^(.*\n)#?\s*$lmd[^\n]*\n|$1$c$lmd\n|s;
            }
            $lmd =~ m|LoadModule\s+(.+?)_module.*|;
            print STDERR "[$what module `$1' in $cfgbase.conf]\n";
        }
        my $amd;
        foreach $amd (@amd) {
            if ($content !~ m|\n#?\s*$amd|) {
                # check for open <containers> etc. see above for explanations.

                my $before = ($content =~ m|^(.*\n)#?\s*AddModule\s+[^\n]+\n|s)[0];
                my $cntopen = () = ($before =~ m|^\s*<[^/].*$|mg);
                my $cntclose = () = ($before =~ m|^\s*</.*$|mg);

                if ($cntopen == $cntclose) {
                    $content =~ s|^(.*\n#?\s*AddModule\s+[^\n]+\n)|$1$c$amd\n|s;
                }
                elsif ($cntopen < $cntclose) {
                    # cannot happen here, but who knows ...
                    print STDERR 'Configuration file is not valid. There are '
                                 . "sections closed before opened.\n";
                    exit(1);
                }
                else {
                    unless ($content =~ s!\A((?:(?:^\s*(?:[^<]|<[^/]).*(?:$)\n)*
                                          ^\s*</.*(?:$)\n?){$cntopen})
                                         !$1$c$amd\n!mx) {
                        # cannot happen here, anyway.
                        print STDERR 'Configuration file is not valid. There '
                                     . "are sections opened and not closed.\n";
                        exit(1);
                    }
                }
            } else {
                # replace already existing AddModule line
                $content =~ s|^(.*\n)#?\s*$amd[^\n]*\n|$1$c$amd\n|s;
            }
        }
        if (@lmd or @amd) {
            if (open(FP, ">$cfgbase.conf.new")) {
                print FP $content;
                close(FP);
                if ($^O ne "MSWin32") {
                    push(@cmds, "cp $cfgbase.conf $cfgbase.conf.bak");
                    push(@cmds, "cp $cfgbase.conf.new $cfgbase.conf");
                    push(@cmds, "rm $cfgbase.conf.new");
                } else {
                    $cfgbase =~ s|/|\\|g;
                    push(@cmds, "copy \"$cfgbase.conf\" \"$cfgbase.conf.bak\"");
                    push(@cmds, "copy \"$cfgbase.conf.new\" \"$cfgbase.conf\"");
                    push(@cmds, "del \"$cfgbase.conf.new\"");
                }
            } else {
                print STDERR "apxs:Error: unable to open configuration file\n";
            }
        }
    }

    #   execute the commands
    &execute_cmds(@cmds);
}

##EOF##
__DATA__
##
##  Makefile -- Build procedure for sample %NAME% Apache module
##  Autogenerated via ``apxs -n %NAME% -g''.
##

#   the used tools
APXS=apxs
APACHECTL=apachectl

#   additional user defines, includes and libraries
#DEF=-Dmy_define=my_value
#INC=-Imy/include/dir
#LIB=-Lmy/lib/dir -lmylib

#   the default target
all: mod_%NAME%.%DSO_EXT%

#   compile the DSO file
mod_%NAME%.%DSO_EXT%: mod_%NAME%.c
	$(APXS) -c $(DEF) $(INC) $(LIB) mod_%NAME%.c

#   install the DSO file into the Apache installation
#   and activate it in the Apache configuration
install: all
	$(APXS) -i -a -n '%NAME%' mod_%NAME%.%DSO_EXT%

#   cleanup
clean:
	-rm -f mod_%NAME%.o mod_%NAME%.%DSO_EXT%

#   simple test
test: reload
	lynx -mime_header http://localhost/%NAME%

#   reload the module by installing and restarting Apache
reload: install restart

#   the general Apache start/restart/stop procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

-=#=-
/* 
**  mod_%NAME%.c -- Apache sample %NAME% module
**  [Autogenerated via ``apxs -n %NAME% -g'']
**
**  To play with this sample module, first compile it into a
**  DSO file and install it into Apache's libexec directory 
**  by running:
**
**    $ apxs -c -i mod_%NAME%.c
**
**  Then activate it in Apache's %TARGET%.conf file, for instance
**  for the URL /%NAME%, as follows:
**
**    #   %TARGET%.conf
**    LoadModule %NAME%_module libexec/mod_%NAME%.%DSO_EXT%
**    <Location /%NAME%>
**    SetHandler %NAME%
**    </Location>
**
**  Then after restarting Apache via
**
**    $ apachectl restart
**
**  you immediately can request the URL /%NAME and watch for the
**  output of this module. This can be achieved for instance via:
**
**    $ lynx -mime_header http://localhost/%NAME% 
**
**  The output should be similar to the following one:
**
**    HTTP/1.1 200 OK
**    Date: Tue, 31 Mar 1998 14:42:22 GMT
**    Server: Apache/1.3.4 (Unix)
**    Connection: close
**    Content-Type: text/html
**  
**    The sample page from mod_%NAME%.c
*/ 

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"

/* The sample content handler */
static int %NAME%_handler(request_rec *r)
{
    r->content_type = "text/html";      
    ap_send_http_header(r);
    if (!r->header_only)
        ap_rputs("The sample page from mod_%NAME%.c\n", r);
    return OK;
}

/* Dispatch list of content handlers */
static const handler_rec %NAME%_handlers[] = { 
    { "%NAME%", %NAME%_handler }, 
    { NULL, NULL }
};

/* Dispatch list for API hooks */
module MODULE_VAR_EXPORT %NAME%_module = {
    STANDARD_MODULE_STUFF, 
    NULL,                  /* module initializer                  */
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    %NAME%_handlers,       /* [#8] MIME-typed-dispatched handlers */
    NULL,                  /* [#1] URI to filename translation    */
    NULL,                  /* [#4] validate user id from request  */
    NULL,                  /* [#5] check if the user is ok _here_ */
    NULL,                  /* [#3] check access by host address   */
    NULL,                  /* [#6] determine MIME type            */
    NULL,                  /* [#7] pre-run fixups                 */
    NULL,                  /* [#9] log a transaction              */
    NULL,                  /* [#2] header parser                  */
    NULL,                  /* child_init                          */
    NULL,                  /* child_exit                          */
    NULL                   /* [#0] post read-request              */
};

