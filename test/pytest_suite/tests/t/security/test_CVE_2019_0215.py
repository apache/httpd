r"""Translated from t/security/CVE-2019-0215.t -- mod_ssl PHA access-control bypass.

CVE-2019-0215: under TLS 1.3 Post-Handshake Auth, a per-directory access check
could be bypassed. Against the ssl_optional_cc vhost, requesting a client-cert-
required location WITHOUT presenting a cert must be denied on every request.

The Perl test uses TLS 1.3 if available (expecting 403) and falls back to 500 on
older TLS. With PHA enabled in client.py, httpx negotiates TLS 1.3, so we expect
403 (access denied without a client certificate) on repeated requests.
"""

from apache_pytest import need_ssl, t_cmp


@need_ssl()
def test_cve_2019_0215(http):
    http.scheme("https")
    http.module("ssl_optional_cc")

    # TLS 1.3 PHA path: access to /require/any without a client cert -> 403,
    # consistently across requests (no bypass on a reused connection).
    r = http.GET("/require/any/", cert=None)
    assert t_cmp(r.status_code, 403), "first access denied without client cert"

    r = http.GET("/require/any/", cert=None)
    assert t_cmp(r.status_code, 403), "second access denied without client cert"
