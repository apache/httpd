r"""Translated from t/apache/pr64339.t -- mod_xml2enc charset handling via proxy.

Only valid on 2.4.x (>= 2.4.59 and < 2.5.0); mod_xml2enc on trunk behaves
differently after r1785780.

Needs: xml2enc, alias, proxy_html, proxy.
"""

import re

import pytest

from apache_pytest import need_module, t_cmp

# (path, expected Content-Type, expected body regex)
TESTCASES = [
    ("/doc.xml", "application/xml; charset=utf-8", "fóó\n"),
    ("/doc.fooxml", "application/foo+xml; charset=utf-8", "fóó\n"),
    ("/doc.notxml", "application/notreallyxml", "f\xf3\xf3\n"),
    ("/doc.isohtml", "text/html;charset=utf-8", "<html><body>.*fóó\n.*</body></html>"),
]


@need_module("xml2enc", "alias", "proxy_html", "proxy")
@pytest.mark.parametrize("path,ctype,body", TESTCASES, ids=lambda v: str(v))
def test_pr64339(http, path, ctype, body):
    if http.have_min_apache_version("2.5.0"):
        pytest.skip("Test only valid for 2.4.x")
    if not http.have_min_apache_version("2.4.59"):
        pytest.skip("Test not valid before 2.4.59")

    r = http.GET("/modules/xml2enc/front" + path)
    assert t_cmp(r.status_code, 200), f"fetching {path}"
    assert t_cmp(r.headers.get("Content-Type"), ctype), (
        f"content-type header test for {path}"
    )
    assert t_cmp(r.text, re.compile(body, re.DOTALL)), f"content test for {path}"
