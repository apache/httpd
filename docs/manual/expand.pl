#!/usr/bin/perl

# This is a very simple Perl script to expand server-side includes
# in the directory it is run, and direct subdirectories. It will
# work only on SSI directives of the form
#
# <!--#include virtual="filename" -->
#
# Filename must be relative to the directory the file appears in.
#
# Nov 30, 1996 - Alexei Kosut <akosut@apache.org>

# ====================================================================
# The Apache Software License, Version 1.1
#
# Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
# reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The end-user documentation included with the redistribution,
#    if any, must include the following acknowledgment:
#       "This product includes software developed by the
#        Apache Software Foundation (http://www.apache.org/)."
#    Alternately, this acknowledgment may appear in the software itself,
#    if and wherever such third-party acknowledgments normally appear.
#
# 4. The names "Apache" and "Apache Software Foundation" must
#    not be used to endorse or promote products derived from this
#    software without prior written permission. For written
#    permission, please contact apache@apache.org.
#
# 5. Products derived from this software may not be called "Apache",
#    nor may "Apache" appear in their name, without prior written
#    permission of the Apache Software Foundation.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# ====================================================================
#
# This software consists of voluntary contributions made by many
# individuals on behalf of the Apache Software Foundation.  For more
# information on the Apache Software Foundation, please see
# <http://www.apache.org/>.
#

# Put a list of dirs (except ..) into @dirs

opendir DIR, "." or die "Could not open directory: $!";
@dirs = grep !/^\.\.$/, (grep -d, readdir DIR);
closedir DIR;

foreach $dir (@dirs) {
    print "Entering directory $dir\n";
    opendir SUBDIR, "$dir" or die "Could not open subdir $dir: $!";
    foreach $file (grep /\.html(\.[^.]+)*$/, readdir SUBDIR) {
	print "Expanding file $dir/$file\n";
	rename "$dir/$file", "$dir/${file}.old";
	open READ, "$dir/${file}.old" or die "Couldn't read $dir/$file: $!";
	open WRITE, ">$dir/$file" or die "Couldn't write $dir/$file: $!";
	while ($r = <READ>) {
	    if ($r =~ /<!--#include virtual="(.*)" -->/) {
		($pre, $include, $post) = ($`, $1, $');
		print WRITE $pre;

		open INC, "$dir/$include" or
		    print "Could not include file $dir/$include: $!";
		print WRITE while (<INC>);
		close INC;

		print WRITE $post;
	    }
	    else {
		print WRITE $r;
	    }
	}
	close READ;
	close WRITE;
	unlink "$dir/$file.old";
    }
    closedir SUBDIR;
}


