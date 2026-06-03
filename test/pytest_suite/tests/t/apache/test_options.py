r"""Translated from t/apache/options.t -- OPTIONS method on the server root.

Perl original:
    plan tests => @urls * 2, \&need_lwp;
    for my $url (@urls) {
        my $res = OPTIONS $url;
        ok t_cmp $res->code, 200, "code";
        ok t_cmp $res->header('Allow'), qr/OPTIONS/, "OPTIONS";
    }
"""

import re

import pytest

from apache_pytest import need_lwp, t_cmp

URLS = ["/"]


@need_lwp()
@pytest.mark.parametrize("url", URLS)
def test_options(http, url):
    res = http.OPTIONS(url)
    assert t_cmp(res.status_code, 200), "code"
    assert t_cmp(res.headers.get("Allow", ""), re.compile("OPTIONS")), "OPTIONS"
