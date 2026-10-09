r"""Translated from t/ssl/basicauth.t.

SSLOptions +FakeBasicAuth at /ssl-fakebasicauth: the client cert's subject DN
(one-line form) becomes the Basic-auth username, checked against ssl.htpasswd
(which the SSL CA seeds with the client_snakeoil DN + password "password").

* no cert        -> 500 (TLS abort) or 403
* client_snakeoil -> 200 (its DN is in ssl.htpasswd)
* client_ok       -> 401 (DN not in ssl.htpasswd)
* client_colon    -> 403 (>= 2.5.1: colon in username rejected)

(user_agent_keepalive(0) is a no-op here; per-cert httpx clients don't share a
TLS session.)
"""

import re

from apache_pytest import need_module, need_ssl
from apache_pytest.testapi import t_cmp


@need_ssl()
@need_module("auth_basic")
def test_basicauth(http):
    http.scheme("https")
    url = "/ssl-fakebasicauth/index.html"

    assert t_cmp(
        http.GET_RC(url, cert=None), re.compile(r"^(500|403)$")
    ), f"Getting {url} with no cert"

    assert http.GET_RC(url, cert="client_snakeoil") == 200, (
        f"Getting {url} with client_snakeoil cert"
    )

    assert http.GET_RC(url, cert="client_ok") == 401, (
        f"Getting {url} with client_ok cert"
    )

    if http.have_min_apache_version("2.5.1"):
        assert http.GET_RC(url, cert="client_colon") == 403, (
            f"Getting {url} with client_colon cert"
        )
