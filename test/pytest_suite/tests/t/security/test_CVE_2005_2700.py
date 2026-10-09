r"""Translated from t/security/CVE-2005-2700.t -- SSLVerifyClient optional+/require.

Against the ssl_optional_cc vhost: a location with no client-cert requirement is
reachable without a cert (200), while a location that requires one is not (non-200)
when no client cert is presented.
"""

from apache_pytest import need_ssl, t_cmp


@need_ssl()
def test_cve_2005_2700(http):
    http.scheme("https")
    http.module("ssl_optional_cc")

    r = http.GET("/require/none/")
    assert t_cmp(r.status_code, 200), "access permitted without ccert"

    r = http.GET("/require/any/")
    assert not t_cmp(r.status_code, 200), "access *not* permitted without ccert"
