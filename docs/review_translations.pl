#!/opt/local/bin/perl
use XML::Simple;
use Getopt::Std;
use File::Glob;
use Data::Dumper;
use strict;

our ( $opt_m, $opt_x );
our $VERSION = '0.01';
our %LANGS = (
        'fr' => 'French',
        );

getopt("m:");
HELP_MESSAGE() unless $opt_m;

my $eng = $opt_m . '.xml';
my @files = glob $opt_m . '.xml.*';

my $xs = XML::Simple->new();
my $eng_xml = $xs->XMLin( $eng );

print "This document defines the following directives:\n";
my @directives;
foreach my $directive ( keys %{ $eng_xml->{directivesynopsis} } ) {
    push @directives, $directive;
    print $directive . "\n";
}
print "\n";

foreach my $file (@files) {
    next if $file =~ m/\.meta$/;
    my $lang = $file;
    $lang =~ s/.*\.([^.]+)$/$1/;
    print "Translation available in ". ($LANGS{$lang}?$LANGS{$lang}:$lang) ."\n";
    my $lang_xml = $xs->XMLin( $file );

    foreach my $d ( @directives ) {
        print "Translation does not define $d\n" unless defined( $lang_xml->{directivesynopsis}->{$d} );
    }
    
    print "\n\n";
}


sub HELP_MESSAGE {
    print STDERR qq~

Usage: 

cd manual/mod
../../review_translations.pl -m mod_rewrite

Lists languages with available translations, and tells you what
directives are missing from each translation.

-m mod_foo - Run for mod_foo.

-x - Generate XML for missing directives, to be pasted into the
translation XML.

~;
}


