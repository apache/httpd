r"""Translated from t/ssl/env.t.

GETs a CGI that echoes %ENV over https and checks the mod_ssl SSL_* DN
environment variables:

* SSL_SERVER_I_DN_* : the server certificate's *issuer* DN == the test CA DN.
* SSL_CLIENT_S_DN_* : the presented client cert's *subject* DN.

Two requests:
  1. /ssl-cgi/env.pl with no client cert -- the SSL_SERVER_I_DN_* vars must be
     present (and correct); the SSL_CLIENT_S_DN_* vars must NOT exist.
  2. /require-ssl-cgi/env.pl with client_snakeoil -- both sets must be present.

Expected DN values mirror apache_pytest/sslca.py's CA_DN and CERT_DN. mod_ssl
exports the emailAddress attribute under the suffix ``_Email``.
"""

from apache_pytest import need_cgi, need_ssl
from apache_pytest.testapi import t_cmp

# CA distinguished name (sslca.py CA_DN) -- the server cert's issuer.
CA_DN = {
    "C": "US",
    "ST": "California",
    "L": "San Francisco",
    "O": "ASF",
    "OU": "httpd-test",
    "CN": "ca",
    "Email": "test-dev@httpd.apache.org",
}

# client_snakeoil subject DN (CA_DN overlaid with sslca.py CERT_DN[client_snakeoil]).
CLIENT_SNAKEOIL_DN = {
    "C": "AU",
    "ST": "Queensland",
    "L": "Mackay",
    "O": "Snake Oil, Ltd.",
    "OU": "Staff",
    "CN": "client_snakeoil",
    "Email": "test-dev@httpd.apache.org",
}


def _dn_vars(dn: dict, prefix: str) -> dict:
    """Apache::TestSSLCA::dn_vars: SSL_<type>_DN_<attr> => value (Email suffix)."""
    return {f"{prefix}_{k}": v for k, v in dn.items()}


def _getenv(body: str) -> dict:
    env = {}
    for line in body.replace("\r", "\n").split("\n"):
        if " = " not in line:
            continue
        key, val = line.split(" = ", 1)
        key, val = key.strip(), val.strip()
        if key and val:
            env[key] = val
    return env


SERVER_EXPECT = _dn_vars(CA_DN, "SSL_SERVER_I_DN")
CLIENT_EXPECT = _dn_vars(CLIENT_SNAKEOIL_DN, "SSL_CLIENT_S_DN")


def _verify_present(env, expect):
    for key, val in expect.items():
        assert key in env and t_cmp(env[key], val), (
            f"{key}: expect {val!r}, got {env.get(key)!r}"
        )


def _verify_absent(env, expect):
    for key in expect:
        assert key not in env, f"{key} should not exist"


@need_ssl()
@need_cgi()
def test_ssl_env(http):
    http.scheme("https")

    r = http.GET("/ssl-cgi/env.pl")
    assert t_cmp(r.status_code, 200), "response status OK"
    env = _getenv(r.text)
    _verify_present(env, SERVER_EXPECT)
    _verify_absent(env, CLIENT_EXPECT)

    r = http.GET("/require-ssl-cgi/env.pl", cert="client_snakeoil")
    assert t_cmp(r.status_code, 200), "second response status OK"
    env = _getenv(r.text)
    _verify_present(env, SERVER_EXPECT)
    _verify_present(env, CLIENT_EXPECT)
