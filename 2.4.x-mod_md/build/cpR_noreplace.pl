#!/usr/bin/perl -w
#
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

use strict;
use File::Basename;
use File::Copy;
use File::Find;
use File::Path qw(mkpath);

require 5.010;

my $srcdir;
my $destdir;

sub process_file {
    return if $_ =~ /^\./;

    my $rel_to_srcdir = substr($File::Find::name, length($srcdir));
    my $destfile = "$destdir$rel_to_srcdir";

    if (-d $File::Find::name) {
        # If the directory is empty, it won't get created.
        # Otherwise it will get created when copying a file.
    }
    else {
        if (-f $destfile) {
            # Preserve it.
        }
        else {
            # Create it.
            my $dir = dirname($destfile);
            if (! -e $dir) {
                mkpath($dir) or die "Failed to create directory $dir: $!";
            }
            copy($File::Find::name, $destfile) or die "Copy $File::Find::name->$destfile failed: $!";
        }
    }
}

$srcdir = shift;
$destdir = shift;
if (scalar(@ARGV) > 0) {
    my $mode = shift;
    if ($mode eq "ifdestmissing") {
        # Normally the check for possible overwrite is performed on a
        # file-by-file basis.  If "ifdestmissing" is specified and the
        # destination directory exists, bail out.
        if (-d $destdir) {
            print "[PRESERVING EXISTING SUBDIR $destdir]\n";
            exit(0);
        }
    }
    else {
        die "bad mode $mode";
    }
}
find(\&process_file, ($srcdir));
