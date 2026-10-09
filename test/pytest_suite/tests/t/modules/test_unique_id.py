"""Translated from t/modules/unique_id.t -- mod_unique_id.

Fetch the unique-id CGI 100 times; each must return 200, a value of length
>= 20, and a value not seen before.

Perl original used ``need need_cgi, need_module('unique_id')``.
"""

from apache_pytest import need_cgi, need_module, t_cmp

ITERS = 100
URL = "/modules/cgi/unique-id.pl"


@need_cgi()
@need_module("unique_id")
def test_unique_id(http):
    seen = set()
    for _ in range(ITERS):
        r = http.GET(URL)
        assert t_cmp(r.status_code, 200), "fetch unique ID"
        v = r.text.rstrip("\r\n")
        assert len(v) >= 20
        assert v not in seen
        seen.add(v)
