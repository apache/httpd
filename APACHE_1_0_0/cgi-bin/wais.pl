#!/usr/local/bin/perl
#
# wais.pl -- WAIS search interface
#
# wais.pl,v 1.2 1994/04/10 05:33:29 robm Exp
#
# Tony Sanders <sanders@bsdi.com>, Nov 1993
#
# Example configuration (in local.conf):
#     map topdir wais.pl &do_wais($top, $path, $query, "database", "title")
#

$waisq = "/usr/local/bin/waisq";
$waisd = "/u/Web/wais-sources";
$src = "www";
$title = "NCSA httpd documentation";

sub send_index {
    print "Content-type: text/html\n\n";
    
    print "<HEAD>\n<TITLE>Index of ", $title, "</TITLE>\n</HEAD>\n";
    print "<BODY>\n<H1>", $title, "</H1>\n";

    print "This is an index of the information on this server. Please\n";
    print "type a query in the search dialog.\n<P>";
    print "You may use compound searches, such as: <CODE>environment AND cgi</CODE>\n";
    print "<ISINDEX>";
}

sub do_wais {
#    local($top, $path, $query, $src, $title) = @_;

    do { &'send_index; return; } unless defined @ARGV;
    local(@query) = @ARGV;
    local($pquery) = join(" ", @query);

    print "Content-type: text/html\n\n";

    open(WAISQ, "-|") || exec ($waisq, "-c", $waisd,
                                "-f", "-", "-S", "$src.src", "-g", @query);

    print "<HEAD>\n<TITLE>Search of ", $title, "</TITLE>\n</HEAD>\n";
    print "<BODY>\n<H1>", $title, "</H1>\n";

    print "Index \`$src\' contains the following\n";
    print "items relevant to \`$pquery\':<P>\n";
    print "<DL>\n";

    local($hits, $score, $headline, $lines, $bytes, $type, $date);
    while (<WAISQ>) {
        /:score\s+(\d+)/ && ($score = $1);
        /:number-of-lines\s+(\d+)/ && ($lines = $1);
        /:number-of-bytes\s+(\d+)/ && ($bytes = $1);
        /:type "(.*)"/ && ($type = $1);
        /:headline "(.*)"/ && ($headline = $1);         # XXX
        /:date "(\d+)"/ && ($date = $1, $hits++, &docdone);
    }
    close(WAISQ);
    print "</DL>\n";

    if ($hits == 0) {
        print "Nothing found.\n";
    }
    print "</BODY>\n";
}

sub docdone {
    if ($headline =~ /Search produced no result/) {
        print "<HR>";
        print $headline, "<P>\n<PRE>";
# the following was &'safeopen
        open(WAISCAT, "$waisd/$src.cat") || die "$src.cat: $!";
        while (<WAISCAT>) {
            s#(Catalog for database:)\s+.*#$1 <A HREF="/$top/$src.src">$src.src</A>#;
            s#Headline:\s+(.*)#Headline: <A HREF="$1">$1</A>#;
            print;
        }
        close(WAISCAT);
        print "\n</PRE>\n";
    } else {
        print "<DT><A HREF=\"$headline\">$headline</A>\n";
        print "<DD>Score: $score, Lines: $lines, Bytes: $bytes\n";
    }
    $score = $headline = $lines = $bytes = $type = $date = '';
}

open (STDERR,"> /dev/null");
eval '&do_wais';
