r"""Translated from t/security/CVE-2007-5000.t -- mod_imagemap XSS escaping.

Perl original (plan tests => 2, need_imagemap):
    my $url = '/security/CVE-2005-3352.map/<foo>';
    my $r = GET $url;
    ok t_cmp($r->code, 200, "response code is OK");
    ok !t_cmp($r->content, qr/<foo>/, "URI was escaped in response");

need_imagemap maps to need_module('imagemap'); skipped where mod_imagemap is
not built.
"""

import re

from apache_pytest import need_module, t_cmp

URL = "/security/CVE-2005-3352.map/<foo>"


@need_module("imagemap")
def test_cve_2007_5000(http):
    r = http.GET(URL)
    assert t_cmp(r.status_code, 200), "response code is OK"
    assert not t_cmp(r.text, re.compile(r"<foo>")), "URI was escaped in response"
