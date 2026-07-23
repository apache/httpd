r"""Translated from t/ssl/require.t -- SSLRequire client-cert access control.

Exercises the ``cert =>`` request option: presenting different client certs
(client_ok / client_revoked / client_snakeoil / none) against locations that
require specific certs, asserting the resulting status codes.

Perl original used Apache::TestRequest::scheme('https') + GET_RC(url, cert => ...).
Here the `http` fixture's scheme('https') routes to the mod_ssl vhost and
verifies against the generated test CA; cert='name' presents proxy/<name>.pem.
"""

from apache_pytest import need_ssl


@need_ssl()
def test_sslrequire(http):
    http.scheme("https")

    url = "/require/asf/index.html"
    assert http.GET_RC(url, cert=None) != 200
    assert http.GET_RC(url, cert="client_ok") == 200
    assert http.GET_RC(url, cert="client_revoked") != 200

    url = "/require/snakeoil/index.html"
    assert http.GET_RC(url, cert="client_ok") != 200
    assert http.GET_RC(url, cert="client_snakeoil") == 200

    assert http.GET_RC("/require/strcmp/index.html", cert=None) == 200
    assert http.GET_RC("/require/intcmp/index.html", cert=None) == 200

    # certificate-extension (SSLRequire OID) checks: needs httpd >= 2.1.7,
    # and the client_ok positive case is only valid on >= 2.4.0.
    if http.have_min_apache_version("2.1.7"):
        url = "/require/certext/index.html"
        assert http.GET_RC(url, cert=None) != 200
        if http.have_min_apache_version("2.4.0"):
            assert http.GET_RC(url, cert="client_ok") == 200
        assert http.GET_RC(url, cert="client_snakeoil") != 200
