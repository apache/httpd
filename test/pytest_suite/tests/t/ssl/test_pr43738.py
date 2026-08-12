r"""Translated from t/ssl/pr43738.t.

A variation of the PR 12355 renegotiation-on-POST test that exercised the path
broken by PR 43738: the .pfa files under /modules/ssl/aes{128,256}/ are mapped
(via mod_actions Action + AddType) to action.pl, which echoes PATH_INFO then the
request body. Each location pins a TLSv1.2 cipher (AES128-SHA / AES256-SHA), so
the POST forces a renegotiation with request-body buffering.

Expected body: "<request-uri>\n<posted-body>".
"""

from apache_pytest import need_min_apache_version, need_module, need_ssl
from apache_pytest.testapi import t_cmp


@need_ssl()
@need_module("actions")
@need_min_apache_version("2.2.7")
def test_pr43738(http):
    http.scheme("https")

    for path in ("/modules/ssl/aes128/empty.pfa", "/modules/ssl/aes256/empty.pfa"):
        r = http.POST(path, content="hello world")
        assert t_cmp(r.status_code, 200), "renegotiation on POST works"
        assert t_cmp(r.text.replace("\r\n", "\n"), f"{path}\nhello world"), \
            "request body matches response"
