"""Translated from t/modules/brotli.t -- mod_brotli content negotiation.

For each Accept-Encoding qvalue variant, GET/HEAD the brotli location and a
zero-length file and assert whether the response is "br" encoded (per the
expected flag), plus that Content-Length and ETag are always present. If
mod_deflate is present, also check br-vs-gzip preference ordering.

Perl original used ``need_module 'brotli', need_module 'alias'``.
"""

import pytest

from apache_pytest import need_module, t_cmp

# (qvalue suffix appended after "br", expected-br flag)
QVALUES = [
    ("", 1),
    (" ", 1),
    (";", 1),
    (";q=", 1),
    (";q=0", 0),
    (";q=0.", 0),
    (";q=0.0", 0),
    (";q=0.00", 0),
    (";q=0.000", 0),
    (";q=0.0000", 1),  # invalid qvalue format
]


def _check(r, expect_br):
    assert t_cmp(r.status_code, 200)
    if expect_br == 1:
        assert t_cmp(r.headers.get("Content-Encoding"), "br"), \
            "response Content-Encoding is OK"
    else:
        assert t_cmp(r.headers.get("Content-Encoding"), None), \
            "response without Content-Encoding is OK"
    assert r.headers.get("Content-Length") is not None, "Content-Length was expected"
    assert r.headers.get("ETag") is not None, "ETag field was expected"


@need_module("brotli", "alias")
@pytest.mark.parametrize("suffix,expect_br", QVALUES, ids=lambda v: repr(v))
def test_brotli_qvalue(http, suffix, expect_br):
    ae = "br" + suffix
    # httpx rejects header values containing whitespace (LWP allowed them);
    # skip the whitespace-only qvalue variant (framework/httpx gap).
    if any(c.isspace() for c in ae):
        pytest.skip("httpx rejects whitespace in Accept-Encoding header value")
    _check(http.GET("/only_brotli/index.html", headers={"Accept-Encoding": ae}),
           expect_br)
    _check(http.GET("/only_brotli/zero.txt", headers={"Accept-Encoding": ae}),
           expect_br)
    _check(http.HEAD("/only_brotli/index.html", headers={"Accept-Encoding": ae}),
           expect_br)


@need_module("brotli", "alias")
def test_brotli_deflate_preference(http):
    if not http.have_module("deflate"):
        pytest.skip("skipping tests without mod_deflate")

    # Brotli is chosen due to the order in SetOutputFilter.
    r = http.GET("/brotli_and_deflate/apache_pb.gif",
                 headers={"Accept-Encoding": "gzip,br"})
    assert t_cmp(r.status_code, 200)
    assert t_cmp(r.headers.get("Content-Encoding"), "br"), \
        "response Content-Encoding is OK"
    assert r.headers.get("Content-Length") is not None
    assert r.headers.get("ETag") is not None

    r = http.GET("/brotli_and_deflate/apache_pb.gif",
                 headers={"Accept-Encoding": "gzip"})
    assert t_cmp(r.status_code, 200)
    assert t_cmp(r.headers.get("Content-Encoding"), "gzip"), \
        "response Content-Encoding is OK"
    assert r.headers.get("Content-Length") is not None
    assert r.headers.get("ETag") is not None
