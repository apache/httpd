r"""Translated from t/http11/all.t -- HTTP/1.1 availability gate.

Perl original:
    plan tests => 1, \&need_http11;   # skip the dir unless client has HTTP/1.1
    ok 1;

The Python client (httpx) always speaks HTTP/1.1, so this is unconditionally OK.
"""


def test_http11_available():
    assert True
