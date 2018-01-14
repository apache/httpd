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

use Carp;

my $path=shift || '.';

findInDir($path);

foreach my $hook (sort keys %::Hooks) {
    my $h=$::Hooks{$hook};
    for my $x (qw(declared implemented type args)) {
	print "$hook datum '$x' missing\n" if !exists $h->{$x};
    }
    print "$hook\n";
    print "  declared in $h->{declared}\n" if defined $h->{declared};
    print "  implemented in $h->{implemented}\n" if defined $h->{implemented};
    print "  type is $h->{type}\n" if defined $h->{type};
    print "  $h->{ret} $hook($h->{args})\n" if defined $h->{args};
    print "\n";
}

sub findInDir {
    my $path=shift;

    local(*D);
    opendir(D,$path) || croak "Can't open $path: $!";
    while(my $f=readdir D) {
	next if $f=~/^\./;
	my $file="$path/$f";

	if(-d $file) {
	    findInDir($file);
	    next;
	}
	next if $file !~ /\.[ch]$/;

	scanFile($file);
    }
    closedir D;
}

sub scanFile {
    my $file=shift;

#   print "scanning $file\n";

    open(F,$file) || croak "Can't open $file: $!";
    while(<F>) {
	next if /\#define/;
	next if /\@deffunc/;
	if(/AP_DECLARE_HOOK\s*\(/) {
	    my($ret,$name,$args);
	    while(!(($ret,$name,$args)=
		   /AP_DECLARE_HOOK\s*\(\s*([^,]+)\s*,\s*([^,\s]+)\s*,\s*\((.*?)\)\)/s)) {
		chomp;
		# swallow subsequent lines if needed to get all the required info
		my $l=<F>;
		return unless defined $l;
		$l=~s/^\s*/ /;
		$_.=$l;
	    }
	    $ret=~s/\s*$//;
	    $args=~s/^\s*//; $args=~s/\s*$//;
#	    print "found $ret $name($args) in $file\n";

	    croak "$name declared twice! ($_)"
		if exists $::Hooks{$name}->{declared};
	    $::Hooks{$name}->{declared}=$file;
	    $::Hooks{$name}->{ret}=$ret;
	    $::Hooks{$name}->{args}=$args;
	}
	if(/AP_IMPLEMENT_HOOK_()(VOID)\(([^,\s]+)/
	   || /AP_IMPLEMENT(_OPTIONAL|)_HOOK_(.*?)\([^,]+?\s*,\s*([^,\s]+)/) {
	    my($type,$name)=($1 ? "OPTIONAL $2" : $2,$3);

#	    print "found $name $type in $file\n";

	    croak "$name implemented twice ($::Hooks{$name}->{implemented} and $file) ($_)"
		if exists $::Hooks{$name}->{implemented};
	    $::Hooks{$name}->{implemented}=$file;
	    $::Hooks{$name}->{type}=$type;
	}
    }
}
