r"""Translated from t/php/strings.t -- need_php.

The Perl expected literal was the double-quoted string

    "\"\t\\'\\n\\'a\\\\b\\"

which interpolates to these exact characters: a double quote, a tab, then the
literal sequence  \'\n\'a\\b\  (backslashes are literal, not escapes). The
Python literal below reproduces the identical bytes.
"""

from apache_pytest import need_php

EXPECTED = '"\t\\\'\\n\\\'a\\\\b\\'


@need_php()
def test_strings(http):
    result = http.GET_BODY("/php/strings.php")
    assert result == EXPECTED
