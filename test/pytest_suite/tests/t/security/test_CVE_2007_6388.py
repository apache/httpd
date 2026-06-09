r"""Translated from t/security/CVE-2007-6388.t -- mod_status Refresh XSS.

Perl original (plan tests => 2, need_module 'status'):
    my $url = '/server-status?refresh=42;fish';
    my $r = GET $url;
    ok t_cmp($r->code, 200, "response code is OK");
    ok t_cmp($r->header('Refresh'), 42, "refresh parameter not echoed verbatim");
"""

from apache_pytest import need_module, t_cmp


@need_module("status")
def test_cve_2007_6388(http):
    r = http.GET("/server-status?refresh=42;fish")
    assert t_cmp(r.status_code, 200), "response code is OK"
    assert t_cmp(r.headers.get("Refresh"), 42), "refresh parameter not echoed verbatim"
