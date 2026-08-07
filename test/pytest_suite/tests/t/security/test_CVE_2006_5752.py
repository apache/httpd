r"""Translated from t/security/CVE-2006-5752.t -- mod_status XSS charset.

Perl original (plan tests => 2, need_module 'status'):
    $r = GET "/server-status";
    ok t_cmp($r->code, 200, "server-status gave response");
    ok t_cmp($r->header("Content-Type"), qr/charset=/, "response content-type had charset");
"""

import re

from apache_pytest import need_module, t_cmp


@need_module("status")
def test_cve_2006_5752(http):
    r = http.GET("/server-status")
    assert t_cmp(r.status_code, 200), "server-status gave response"
    assert t_cmp(r.headers.get("Content-Type", ""), re.compile(r"charset=")), (
        "response content-type had charset"
    )
