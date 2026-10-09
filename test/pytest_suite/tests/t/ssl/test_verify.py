r"""Translated from t/ssl/verify.t -- SSLVerifyClient at the /verify location.

Presenting no cert / a valid cert / a revoked cert against a location that
requires client-cert verification, asserting access is denied / granted /
denied respectively. (user_agent_keepalive(0) in the Perl original is a no-op
here: each client cert uses its own httpx client, so no session is reused.)
"""

from apache_pytest import need_ssl


@need_ssl()
def test_sslverifyclient(http):
    http.scheme("https")

    url = "/verify/index.html"
    assert http.GET_RC(url, cert=None) != 200
    assert http.GET_RC(url, cert="client_ok") == 200
    assert http.GET_RC(url, cert="client_revoked") != 200
