r"""Translated from t/apr/uri.t -- apr_uri parsing self-test.

Perl original (plan tests => 1, need_module 'test_apr_uri'):
    my $body = GET_BODY '/test_apr_uri';
    ok $body =~ /TOTAL\s+FAILURES\s*=\s*0/;

The test_apr_uri C module runs apr_uri unit cases and reports a failure count.
"""

import re

from apache_pytest import need_module


@need_module("test_apr_uri")
def test_apr_uri(http):
    body = http.GET_BODY("/test_apr_uri")
    assert re.search(r"TOTAL\s+FAILURES\s*=\s*0", body)
