#!/usr/local/bin/perl5 -w
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
# manual-index.cgi script
# originally written by Ken Coar <Coar@DECUS.Org> in May 1997
#
# This script either displays a form in order to find documents in which
# a word appears, or displays the results of such a search.  It is
# called as a CGI script.
#
# [FILE]PATH_INFO is the prefix to add to to the files names found in
# the index (URL prefix, not filesystem prefix), and QUERY_STRING is the
# word to be found.
#
#***
#***
# You may need to tweak the following line to point to the correct
# location of the index file on your system (it's in the
# apache/htdocs/manual directory of the Apache distribution tree).
#***
#***
$INDEX = "/www/apache.org/manual-index-data";

#***
#***
# You shouldn't have to modify anything else.
#***
#***

$HTML = "";

#
# If we have a FILEPATH_INFO or PATH_INFO, it's there to remap the
# documents to the manual root directory.  If this script is already in
# that directory, this isn't needed.
#
$prefix = $ENV{'FILEPATH_INFO'} || $ENV{'PATH_INFO'};
$prefix .= "/" if ($prefix && ($prefix !~ m:/$:));

#
# QUERY_STRING, if present, contains the word for which we are to
# search.  We also  use its [non]presence to determine wha we display.
#
$word = $ENV{'QUERY_STRING'};

#
# Make sure our HTTP header makes it to the server by causing Perl to do
# a fflush() after every write to STDOUT.
#
select (STDOUT);
$| = 1;
printf ("Content-type: text/html\n\n");

#
# Fine, now buffering can go back to normal.
#
$| = 0;

#
# Set up the HTML page title
$title = "Apache Documentation Search";
$title .= ": Results for \"$word\"" if ($word);

#
# We'll re-use the HTML scalar several times; we use it with here
# documents for multi-line static HTML code.  Lets' do the standard page
# header.
#
$HTML = <<EOHT;
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<HTML>
 <HEAD>
  <TITLE>$title
  </TITLE>
 </HEAD>
<!-- Background white, links blue (unvisited), navy (visited), red (active) -->
 <BODY
  BGCOLOR="#FFFFFF"
  TEXT="#000000"
  LINK="#0000FF"
  VLINK="#000080"
  ALINK="#FF0000"
 >
  <DIV ALIGN="CENTER">
   <IMG
    SRC="${prefix}images/sub.gif"
    ALT=""
   >
  </DIV>
  <H1 ALIGN="CENTER">
   Apache Documentation Search
  </H1>
  <P>
  This script performs a very simple search across the Apache
  documentation for any single case-insensitive word.  No combinations,
  wildcards, regular expressions, word-stubbing, or other fancy options
  are supported; this is just to help you find topics quickly.  Only
  those pages which include the <EM>exact</EM> word you type will be
  listed.
  </P>
  <P>
  Documents containing the search word are <EM>not</EM> listed in any
  sort of priority order.
  </P>
  <ISINDEX PROMPT="Enter word to find and press ENTER: ">
EOHT

printf ($HTML);

#
# Now set up the next section, which is only displayed if we've been
# given a word to find.
#
$HTML = <<EOHT;
  <HR>
  <H2>
   Results of Search for <SAMP>$word</SAMP>
  </H2>
EOHT

#
# We enblock the next section so problems can drop out to the common
# closure code.
#
QUERY:
    {
	if ($word) {
	    #
	    # Try and open the index file; complain bitterly if we can't.
	    #
	    if (! open (INDEX, "<$INDEX")) {
		printf ("Can't find documentation index!");
		last QUERY;
	    }
	    #
	    # Got it; display the search-results header.
	    #
	    printf ($HTML);
	    #
	    # Read the entire index in and turn it into an hash for the
	    # lookup.
	    #
	    @index = <INDEX>;
	    close (INDEX);
	    chomp (@index);
	    foreach (@index) {
		($key, $files) = split (/:/, $_);
		$Index{$key} = $files;
	    }
	    #
	    # The dictionary is all lowercase words.  Smash our query value
	    # and try to find it.
	    #
	    $word = lc ($word);
	    if (! exists ($Index{$word})) {
		printf ("  <P>\n  <EM>Sorry, no matches found.</EM>\n  </P>\n");
		last QUERY;
	    }
	    #
	    # Found an entry, so turn the hash value (a comma-separated list
	    # of relative file names) into an array for display.
	    # Incidentally, tell the user how many there are.
	    #
	    @files = split (/,/, $Index{$word});
	    printf ("  <P>Total of %d match", scalar (@files));
	    #
	    # Be smart about plurals.
	    #
	    if (scalar (@files) != 1) {
		printf ("es") ;
	    }
	    printf (" found.\n  </P>\n");
	    #
	    # Right.  Now display the files as they're listed.
	    #
	    printf ("  <OL>\n");
	    foreach (@files) {
		printf ("   <LI><A HREF=\"${prefix}$_\">");
		printf ("<SAMP>$_</SAMP></A>\n");
		printf ("   </LI>\n");
	    }
	    printf ("  </OL>\n");
	    #
	    # C'est tout!
	    #
	}
    }

#
# Back to common code - the exit path.  Display the page trailer.
#
$HTML = <<EOHT;
  <A
   HREF="/"
  ><IMG
    SRC="/images/apache_home.gif"
    ALT="Home"
   ></A>
  <HR>
 </BODY>
</HTML>
EOHT

printf ($HTML);
exit (0);
