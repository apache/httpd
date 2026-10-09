"""Translated from t/php/strings4.t -- need_php.

Expected output contains Latin-1 characters (htmlentities of non-ASCII), kept
verbatim from the Perl heredoc.
"""

from apache_pytest import need_php

EXPECTED = '&lt;&gt;&quot;&amp;åÄ\n&lt;&gt;&quot;&amp;&aring;&Auml;\n'


@need_php()
def test_strings4(http):
    # strings4.php emits ISO-8859-1 bytes (htmlspecialchars of 0xE5/0xC4). FPM
    # sends no response charset, so httpx's .text guesses wrong; decode the raw
    # body as latin-1 so each byte maps 1:1 to the expected codepoint. The PHP
    # output itself is unchanged from PHP4.
    result = http.GET("/php/strings4.php").content.decode("latin-1")
    assert result == EXPECTED
