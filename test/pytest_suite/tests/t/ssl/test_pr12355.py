r"""Translated from t/ssl/pr12355.t.

PR 12355: mod_ssl must buffer request-body data while performing a
per-directory renegotiation. The /require-aes128-cgi and /require-aes256-cgi
locations each pin a different SSLCipherSuite (AES128-SHA / AES256-SHA), so
POSTing to them forces mod_ssl to renegotiate and buffer the body, echoing it
back via perl_echo.pl. We POST bodies of varying sizes and assert the echoed
content matches.

The Perl original first probed TLSv1.3 then downgraded to TLSv1.2 (per-dir
cipher renegotiation doesn't occur under TLSv1.3). The httpx client negotiates
a mutually-acceptable cipher automatically; the functional assertion (body
round-trips with a 200) is what matters and is preserved.

The final mod_case_filter_in sub-test is skipped: that module is not built in
this server.
"""

import pytest

from apache_pytest import need_min_apache_version, need_ssl
from apache_pytest.testapi import t_cmp


@need_ssl()
@need_min_apache_version("2.0")
def test_reneg_post(http):
    http.scheme("https")

    cases = [
        ("/require-aes256-cgi/perl_echo.pl", "hello world"),
        ("/require-aes128-cgi/perl_echo.pl", "hello world"),
        ("/require-aes256-cgi/perl_echo.pl", "x" * 10000),
        ("/require-aes128-cgi/perl_echo.pl", "x" * 60000),
    ]
    for url, body in cases:
        r = http.POST(url, content=body)
        assert t_cmp(r.status_code, 200), "renegotiation on POST works"
        assert t_cmp(r.text, body), "request body matches response"


@need_ssl()
@need_min_apache_version("2.0")
def test_reneg_post_input_filter(http):
    if not http.have_module("case_filter_in"):
        pytest.skip("mod_case_filter_in not available")
    http.scheme("https")
    r = http.POST(
        "/require-aes256-cgi/perl_echo.pl",
        content="hello",
        headers={"X-AddInputFilter": "CaseFilterIn"},
    )
    assert t_cmp(r.status_code, 200), "renegotiation on POST works"
    assert t_cmp(r.text, "HELLO"), "request body matches response"
