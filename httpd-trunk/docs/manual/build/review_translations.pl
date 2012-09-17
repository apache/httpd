#!/opt/local/bin/perl
use XML::Simple;
use Getopt::Std;
use File::Glob;
use Data::Dumper;
use strict;

our ( $opt_m, $opt_x, $opt_l );
our $VERSION = '0.01';
our %LANGS = (
        'fr' => 'French',
        'ja' => 'Japanese',
        'de' => 'German',
        'es' => 'Spanish',
        'ko' => 'Korean',
        'tr' => 'Turkish',
        'zh-cn' => 'Simplified Chinese'
        );

getopts("xl:m:");
HELP_MESSAGE() unless $opt_m;

$opt_m =~ s/\.xml$//;
HELP_MESSAGE() unless -f $opt_m . '.xml';

my $eng = $opt_m . '.xml';
my @files = glob $opt_m . '.xml.*';

my $xs = XML::Simple->new();
my $eng_xml = $xs->XMLin( $eng );

print "This document defines the following directives:\n";
my @directives;
foreach my $directive ( sort( keys %{ $eng_xml->{directivesynopsis} } ) ) {
    push @directives, $directive;
    print $directive . "\n";
}
print "\n";

foreach my $file (@files) {

    next if $file =~ m/\.meta$/;
    my $lang = $file;
    $lang =~ s/.*\.([^.]+)$/$1/;

    if ( $opt_l ) {
        next unless $lang eq $opt_l;
    }

    print "Translation available in ". ($LANGS{$lang}?$LANGS{$lang}:$lang) ."\n";
    my $lang_xml = $xs->XMLin( $file );

    my @missing;
    foreach my $d ( @directives ) {
        unless ( defined( $lang_xml->{directivesynopsis}->{$d} ) ) {
            print "Translation does not define $d\n";
            push @missing, $d;
        }
    }

    if ( $opt_x && @missing ) {
        print "\nPaste the following into the XML:\n\n";
        foreach my $d ( @missing ) {
            directive_doc( $d, $eng_xml ) if $opt_x;
        }
    }
    
    print "\n\n";
}

sub directive_doc {
    my ($d, $eng_xml) = @_;

    print "<directivesynopsis>\n";
    print "<name>" . $d . "</name>\n";
    print "<description>" .
        $eng_xml->{directivesynopsis}->{$d}->{description} .
        "</description>\n";
    print "<contextlist>";

    # If there's only one context, this is a scalar, not an arrayref.
    if ( !ref( $eng_xml->{directivesynopsis}->{$d}->{contextlist}->{context}) ) {
        $eng_xml->{directivesynopsis}->{$d}->{contextlist}->{context} 
            = [ $eng_xml->{directivesynopsis}->{$d}->{contextlist}->{context} ]
    }

    foreach my $c ( @{ $eng_xml->{directivesynopsis}->{$d}->{contextlist}->{context} } ) {
        print "<context>".$c."</context>";
    }
    print "</contextlist>\n";
    print "<usage><p>Documentation not yet translated. Please see English version of document.</p></usage>\n";
    print "</directivesynopsis>\n\n";
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

-l xx - Only look at document in language xx

~;

    exit();
}


