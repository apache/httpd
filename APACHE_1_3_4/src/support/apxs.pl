#!/usr/local/bin/perl
## ====================================================================
## Copyright (c) 1998-1999 The Apache Group.  All rights reserved.
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
## 3. All advertising materials mentioning features or use of this
##    software must display the following acknowledgment:
##    "This product includes software developed by the Apache Group
##    for use in the Apache HTTP server project (http://www.apache.org/)."
##
## 4. The names "Apache Server" and "Apache Group" must not be used to
##    endorse or promote products derived from this software without
##    prior written permission. For written permission, please contact
##    apache@apache.org.
##
## 5. Products derived from this software may not be called "Apache"
##    nor may "Apache" appear in their names without prior written
##    permission of the Apache Group.
##
## 6. Redistributions of any form whatsoever must retain the following
##    acknowledgment:
##    "This product includes software developed by the Apache Group
##    for use in the Apache HTTP server project (http://www.apache.org/)."
##
## THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
## EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
## PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
## ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
## SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
## NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
## LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
## HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
## STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
## ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
## OF THE POSSIBILITY OF SUCH DAMAGE.
## ====================================================================
##
## This software consists of voluntary contributions made by many
## individuals on behalf of the Apache Group and was originally based
## on public domain software written at the National Center for
## Supercomputing Applications, University of Illinois, Urbana-Champaign.
## For more information on the Apache Group and the Apache HTTP server
## project, please see <http://www.apache.org/>.
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

my $CFG_TARGET        = '@TARGET@';        # substituted via Makefile.tmpl 
my $CFG_CC            = '@CC@';            # substituted via Makefile.tmpl
my $CFG_CFLAGS        = '@CFLAGS@';        # substituted via Makefile.tmpl
my $CFG_CFLAGS_SHLIB  = '@CFLAGS_SHLIB@';  # substituted via Makefile.tmpl
my $CFG_LD_SHLIB      = '@LD_SHLIB@';      # substituted via Makefile.tmpl
my $CFG_LDFLAGS_SHLIB = '@LDFLAGS_SHLIB@'; # substituted via Makefile.tmpl 
my $CFG_LIBS_SHLIB    = '@LIBS_SHLIB@';    # substituted via Makefile.tmpl 
my $CFG_PREFIX        = '@prefix@';        # substituted via APACI install
my $CFG_SBINDIR       = '@sbindir@';       # substituted via APACI install
my $CFG_INCLUDEDIR    = '@includedir@';    # substituted via APACI install
my $CFG_LIBEXECDIR    = '@libexecdir@';    # substituted via APACI install
my $CFG_SYSCONFDIR    = '@sysconfdir@';    # substituted via APACI install

##
##  Cleanup the above stuff
##
$CFG_CFLAGS =~ s|^\s+||;
$CFG_CFLAGS =~ s|\s+$||;
$CFG_CFLAGS =~ s|\s+`.+apaci`||;

##
##  Initial shared object support check
##
if (not grep(/mod_so/, `$CFG_SBINDIR/$CFG_TARGET -l`)) {
    print STDERR "apxs:Error: Sorry, no shared object support for Apache\n";
    print STDERR "apxs:Error: available under your platform. Make sure\n";
    print STDERR "apxs:Error: the Apache module mod_so is compiled into\n";
    print STDERR "apxs:Error: your server binary `$CFG_SBINDIR/$CFG_TARGET'.\n";
    exit(1);
}

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
my $opt_i = 0;
my $opt_a = 0;
my $opt_A = 0;
my $opt_q = 0;

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
        if($pos >= $[) {
            if($args[$pos+1] eq ':') {
                shift(@ARGV);
                if($rest eq '') {
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
                if($rest eq '') {
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
                if($rest eq '') {
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
            if($rest ne '') {
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
    print STDERR "Usage: apxs -g -n <modname>\n";
    print STDERR "       apxs -q <query> ...\n";
    print STDERR "       apxs -c [-o <dsofile>] [-D <name>[=<value>]] [-I <incdir>]\n";
    print STDERR "               [-L <libdir>] [-l <libname>] [-Wc,<flags>] [-Wl,<flags>]\n";
    print STDERR "               <files> ...\n";
    print STDERR "       apxs -i [-a] [-A] [-n <modname>] <dsofile> ...\n";
    exit(1);
}

#   option handling
my $rc;
($rc, @ARGV) = &Getopts("qn:gco:I+D+L+l+W+iaA", @ARGV);
&usage if ($rc == 0);
&usage if ($#ARGV == -1 and not $opt_g);
&usage if (not $opt_q and not ($opt_g and $opt_n) and not $opt_i and not $opt_c);

#   argument handling
my @args = @ARGV;
my $name = 'unknown';
$name = $opt_n if ($opt_n ne '');

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
            printf(STDERR "apxs:Break: Command failed with rc=%d\n", $rc << 8);
            exit(1);
        }
    }
}

if ($opt_g) {
    ##
    ##  SAMPLE MODULE SOURCE GENERATION
    ##

    if (-d $name) {
        print STDERR "apxs:Error: Directory `$name' already exists. Remove first\n";
        exit(1);
    }

    my $data = join('', <DATA>);
    $data =~ s|%NAME%|$name|sg;
    $data =~ s|%TARGET%|$CFG_TARGET|sg;

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
                $result .= "${val}::";
                $ok = 1;
            }
        }
        if (not $ok) {
            printf(STDERR "apxs:Error: Invalid query string `%s'\n", $arg);
            exit(1);
        }
    }
    $result =~ s|::$||;
    $result =~ s|::| |;
    print $result;
}

if ($opt_c) {
    ##
    ##  SHARED OBJECT COMPILATION
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
            $dso_file =~ s|\.[^.]+$|.so|;
        }
        elsif ($#objs > -1) {
            $dso_file = $objs[0];
            $dso_file =~ s|\.[^.]+$|.so|;
        }
        else {
            $dso_file = "mod_unknown.so";
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
        $opt .= "-I$opt_I ";
    }
    foreach $opt_D (@opt_D) {
        $opt .= "-D$opt_D ";
    }
    my $cflags = "$CFG_CFLAGS $CFG_CFLAGS_SHLIB";
    my $s;
    foreach $s (@srcs) {
        my $o = $s;
        $o =~ s|\.c$|.o|;
        push(@cmds, "$CFG_CC $cflags -I$CFG_INCLUDEDIR $opt -c $s");
        unshift(@objs, $o);
    }

    #   create link command
    my $cmd = "$CFG_LD_SHLIB $CFG_LDFLAGS_SHLIB -o $dso_file";
    my $o;
    foreach $o (@objs) {
        $cmd .= " $o";
    }
    $opt = '';
    my ($opt_Wl, $opt_L, $opt_l);
    foreach $opt_Wl (@opt_W) {
        $opt .= " $1" if ($opt_Wl =~ m|^\s*l,(.*)$|);
    }
    foreach $opt_L (@opt_L) {
        $opt .= " -L$opt_L";
    }
    foreach $opt_l (@opt_l) {
        $opt .= " -l$opt_l";
    }
    $cmd .= $opt;
    $cmd .= " $CFG_LIBS_SHLIB";
    push(@cmds, $cmd);

    #   execute the commands
    &execute_cmds(@cmds);

    #   allow one-step compilation and installation
    if ($opt_i) {
        @args = ( $dso_file );
    }
}

if ($opt_i) {
    ##
    ##  SHARED OBJECT INSTALLATION
    ##

    #   determine installation commands
    #   and corresponding LoadModule/AddModule directives
    my @lmd = ();
    my @amd = ();
    my @cmds = ();
    my $f;
    foreach $f (@args) {
        if ($f !~ m|\.so$|) {
            print STDERR "apxs:Error: file $f is not a shared object\n";
            exit(1);
        }
        my $t = $f;
        $t =~ s|^.+/([^/]+)$|$1|;
        push(@cmds, "cp $f $CFG_LIBEXECDIR/$t");
        push(@cmds, "chmod 755 $CFG_LIBEXECDIR/$t");

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
                    $filename =~ s|^[^/]+/||;
                }
            }
            if ($name eq '') {
                if ($base =~ m|.*mod_([a-zA-Z0-9_]+)\..+|) {
                    $name = "$1";
                    $filename = $base;
                    $filename =~ s|^[^/]+/||;
                }
            }
            if ($name eq '') {
                print "apxs:Error: Sorry, cannot determine bootstrap symbol name\n";
                print "apxs:Error: Please specify one with option `-n'\n";
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

    #   execute the commands
    &execute_cmds(@cmds);

    #   activate module via LoadModule/AddModule directive
    if ($opt_a or $opt_A) {
        if (not -f "$CFG_SYSCONFDIR/$CFG_TARGET.conf") {
            print "apxs:Error: Config file $CFG_SYSCONFDIR/$CFG_TARGET.conf not found\n";
            exit(1);
        }

        open(FP, "<$CFG_SYSCONFDIR/$CFG_TARGET.conf") || die;
        my $content = join('', <FP>);
        close(FP);

        if ($content !~ m|\n#?\s*LoadModule\s+|) {
            print STDERR "apxs:Error: Activation failed for custom $CFG_SYSCONFDIR/$CFG_TARGET.conf file.\n";
            print STDERR "apxs:Error: At least one `LoadModule' directive already has to exist.\n";
            exit(1);
        }

        my $update = 0;
        my $lmd;
        foreach $lmd (@lmd) {
            if ($content !~ m|\n#?\s*$lmd|) {
                 my $c = '';
                 $c = '#' if ($opt_A);
                 $content =~ s|^(.*\n#?\s*LoadModule\s+[^\n]+\n)|$1$c$lmd\n|sg;
                 $update = 1;
                 $lmd =~ m|LoadModule\s+(.+?)_module.*|;
                 my $what = $opt_A ? "preparing" : "activating";
                 print STDERR "[$what module `$1' in $CFG_SYSCONFDIR/$CFG_TARGET.conf]\n";
            }
        }
        my $amd;
        foreach $amd (@amd) {
            if ($content !~ m|\n#?\s*$amd|) {
                 my $c = '';
                 $c = '#' if ($opt_A);
                 $content =~ s|^(.*\n#?\s*AddModule\s+[^\n]+\n)|$1$c$amd\n|sg;
                 $update = 1;
            }
        }
        if ($update) {
            open(FP, ">$CFG_SYSCONFDIR/$CFG_TARGET.conf.new") || die;
            print FP $content;
            close(FP);
            system("cp $CFG_SYSCONFDIR/$CFG_TARGET.conf $CFG_SYSCONFDIR/$CFG_TARGET.conf.bak && " .
                   "cp $CFG_SYSCONFDIR/$CFG_TARGET.conf.new $CFG_SYSCONFDIR/$CFG_TARGET.conf && " .
                   "rm $CFG_SYSCONFDIR/$CFG_TARGET.conf.new");
        }
    }
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

#   additional defines, includes and libraries
#DEF=-Dmy_define=my_value
#INC=-Imy/include/dir
#LIB=-Lmy/lib/dir -lmylib

#   the default target
all: mod_%NAME%.so

#   compile the shared object file
mod_%NAME%.so: mod_%NAME%.c
	$(APXS) -c $(DEF) $(INC) $(LIB) mod_%NAME%.c

#   install the shared object file into Apache 
install: all
	$(APXS) -i -a -n '%NAME%' mod_%NAME%.so

#   cleanup
clean:
	-rm -f mod_%NAME%.o mod_%NAME%.so

#   simple test
test: reload
	lynx -mime_header http://localhost/%NAME%

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
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
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's libexec directory 
**  by running:
**
**    $ apxs -c -i mod_%NAME%.c
**
**  Then activate it in Apache's %TARGET%.conf file for instance
**  for the URL /%NAME% in as follows:
**
**    #   %TARGET%.conf
**    LoadModule %NAME%_module libexec/mod_%NAME%.so
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

