r"""Translated from t/ssl/fakeauth.t.

Fake authentication via mod_auth_anon: no client cert should fail, but the
presence of *any* cert should pass (the /ssl-fakebasicauth2 location uses
SSLOptions +FakeBasicAuth with AuthBasicProvider anon + Anonymous "*").

The no-cert case yields either a 403 (mod_ssl may produce a clean error under
TLSv1.3) or a 500 (an aborted TLS handshake surfaced as a transport failure).
"""

import re

from apache_pytest import need_module, need_ssl
from apache_pytest.testapi import t_cmp


@need_ssl()
@need_module("auth_basic")
@need_module("authn_anon")
def test_fakeauth(http):
    http.scheme("https")
    url = "/ssl-fakebasicauth2/index.html"

    assert t_cmp(
        http.GET_RC(url, cert=None), re.compile(r"^(500|403)$")
    ), f"Getting {url} with no cert"

    assert http.GET_RC(url, cert="client_snakeoil") == 200, (
        f"Getting {url} with client_snakeoil cert"
    )

    assert http.GET_RC(url, cert="client_ok") == 200, (
        f"Getting {url} with client_ok cert"
    )
