#!/usr/bin/perl -w

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

#    print "scanning $file\n";

    open(F,$file) || croak "Can't open $file: $!";
    while(<F>) {
	next if /\#define/;
	next if /\@deffunc/;
	if(/AP_DECLARE_HOOK\((.*)\)/) {
	    my $def=$1;
	    my($ret,$name,$args)=$def=~/([^,\s]+)\s*,\s*([^,\s]+)\s*,\s*\((.*)\)/;
	    croak "Don't understand $def in $file" if !defined $args;
#	    print "found $ret $name($args) in $file\n";

	    croak "$name declared twice! ($_)"
		if exists $::Hooks{$name}->{declared};
	    $::Hooks{$name}->{declared}=$file;
	    $::Hooks{$name}->{ret}=$ret;
	    $::Hooks{$name}->{args}=$args;
	} elsif(/AP_DECLARE_HOOK\((\s*[^,\s]+)\s*,\s*([^,\s]+)/) {
# really we should swallow subsequent lines to get the arguments...
	    my $name=$2;
	    my $ret=$1;
	    croak "$name declared twice! ($_)"
		if exists $::Hooks{$name}->{declared};
	    $::Hooks{$name}->{declared}=$file;
	    $::Hooks{$name}->{ret}=$ret;
	    $::Hooks{$name}->{args}='???';
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
