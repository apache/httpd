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
#
# HOWTO use this to update BaseAddrs.ref:
#
# This takes the old BaseAddrs.ref and a build listing showing LNK4013
# and LNK4198 errors and produces an updated BaseAddrs.ref with any
# necessary changes for incorrect sizes or missing modules.
#
# Missing modules are added with a default size of 64K, so another
# build is needed to determine if a non-default size is required for
# newly added modules.

use strict;

my $oldref = shift;
my $listing = shift;
my $newref = shift;

my $starting_addr = 0x6FF00000;
my $default_size  = 0x00010000;

my @modnames = ();
my @maxsizes = ();
my @comments = ();
my $in_defs = undef;
open(F, "<$oldref") or die;
while (<F>) {
    my $l = $_;
    chomp($l);
    if (!$in_defs && length($l) != 0 && substr($l, 0, 1) ne ';') {
        $in_defs = 1;
    }

    if ($in_defs) {
        my @fields = split(/[ \t]+/, $l);
        @modnames = (@modnames, $fields[0]);
        @maxsizes = (@maxsizes, hex($fields[2]));
    }
    else {
        @comments = (@comments, $l);
    }
}
close(F) or die;

my $curlib = undef;
my %reported = ();
open(F, "<$listing") or die;
while (<F>) {
    my $l = $_;
    chomp($l);

    if ($l =~ /Creating library (.*)\.lib/) {
        if ($1 eq "libhttpd") {
            $curlib = "$1.dll";
        }
        else {
            $curlib = "$1.so";
        }
    }
    elsif ($l =~ /warning LNK4013: image size (.*) exceeds/) {
        my $mod = $curlib;
        my $newsize = hex($1);
        if (!$reported{$mod}) {
            $reported{$mod} = 1;

            # round to nearest 64K
            $newsize = int(1 + $newsize / 0x00010000) * 0x00010000;
            printf "$curlib size changes to %s (rounded to 0x%08X)\n", $1, $newsize;
            my $i = 0;
            while ($i < scalar(@modnames)) {
                if ($modnames[$i] eq $mod) {
                    print "  (from $maxsizes[$i])\n";
                    $maxsizes[$i] = $newsize;
                    last;
                }
                ++$i;
            }
        }
    }
    elsif ($l =~ /warning LNK4198: base key '(.*)' not found/) {
        my $mod = $1;
        if (!$reported{$mod}) {
            $reported{$mod} = 1;
            print "$mod must be added\n";
            @modnames = (@modnames, $mod);
            @maxsizes = (@maxsizes, $default_size);
        }
    }
}
close(F) or die;

open(F, ">$newref") or die;

print F join("\n", @comments);
print F "\n";
my $i = 0;
my $curaddr = $starting_addr;
while ($i < scalar(@modnames)) {
    printf F "%-28s0x%08X    0x%08X\n", $modnames[$i], $curaddr, $maxsizes[$i];
    $curaddr += $maxsizes[$i];
    ++$i;
}
close(F) or die;
