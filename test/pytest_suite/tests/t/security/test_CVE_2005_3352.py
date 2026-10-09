r"""Translated from t/security/CVE-2005-3352.t -- mod_imagemap XSS escaping.

Perl original (plan tests => 2, need_imagemap):
    my $r = GET $url, Referer => '">http://fish/';
    ok t_cmp($r->code, 200, "response code is OK");
    # newer httpd escapes the referer as %22%3e, older as &quot
    ok t_cmp($r->content, qr/.../, "referer was escaped");

need_imagemap maps to need_module('imagemap'); skipped where mod_imagemap is
not built.
"""

import re

from apache_pytest import need_module, t_cmp

URL = "/security/CVE-2005-3352.map"


@need_module("imagemap")
def test_cve_2005_3352(http):
    r = http.GET(URL, headers={"Referer": '">http://fish/'})
    assert t_cmp(r.status_code, 200), "response code is OK"

    no23 = not http.have_min_apache_version("2.3")
    if (no23 and http.have_min_apache_version("2.2.24")) or http.have_min_apache_version(
        "2.4.4"
    ):
        expected = re.compile(r"%22%3e")
    else:
        expected = re.compile(r"\&quot")
    assert t_cmp(r.text, expected), "referer was escaped"
