"""Translated from t/security/CVE-2008-2364.t -- mod_proxy_http interim responses.

Perl original (plan tests => 3 or 1, need_module 'proxy'):
    Apache::TestRequest::module("proxy_http_reverse");
    my $r = GET("/reverse/");
    ok t_cmp($r->code, 200, "reverse proxy to index.html");
    if (have_cgi && server_suppresses_interim) {  # 2.4.10+
        $r = GET("/reverse/modules/cgi/nph-interim1.pl");
        ok t_cmp($r->code, 200, "small number of interim responses - CVE-2008-2364");
        $r = GET("/reverse/modules/cgi/nph-interim2.pl");
        ok t_cmp($r->code, 502, "large number of interim responses - CVE-2008-2364");
    }
"""

from apache_pytest import need_module, t_cmp


@need_module("proxy")
def test_reverse_proxy_index(http):
    http.module("proxy_http_reverse")
    r = http.GET("/reverse/")
    assert t_cmp(r.status_code, 200), "reverse proxy to index.html"


@need_module("proxy")
def test_interim_responses(http):
    import pytest

    if not http.have_min_apache_version("2.4.10"):
        pytest.skip("server does not suppress interim responses before 2.4.10")
    if not (http.have_module("mod_cgi") or http.have_module("mod_cgid")):
        pytest.skip("skipping tests without CGI module")

    http.module("proxy_http_reverse")
    r = http.GET("/reverse/modules/cgi/nph-interim1.pl")
    assert t_cmp(r.status_code, 200), (
        "small number of interim responses - CVE-2008-2364"
    )
    r = http.GET("/reverse/modules/cgi/nph-interim2.pl")
    assert t_cmp(r.status_code, 502), (
        "large number of interim responses - CVE-2008-2364"
    )
