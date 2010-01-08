#!/usr/local/bin/perl5

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ====================================================================

# This is a very simple Perl script to expand server-side includes
# in the directory it is run, and direct subdirectories. It will
# work only on SSI directives of the form
#
# <!--#include virtual="filename" -->
#
# Filename must be relative to the directory the file appears in.
#
# Nov 30, 1996 - Alexei Kosut <akosut@apache.org>

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


