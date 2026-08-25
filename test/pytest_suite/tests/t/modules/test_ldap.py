r"""Translated from t/modules/ldap.t -- mod_authnz_ldap.

Requires an LDAP server (root DN dc=example,dc=com on localhost:8389) populated
from scripts/httpd.ldif, with the suite run with ``--defines LDAP``. Locally the
mod_authnz_ldap module is not built, so these SKIP via @need_module; even where
the module exists, the cases gate on the LDAP define being present.

Perl original:
    plan tests => scalar @cases,
        need need_module('authnz_ldap'), { "LDAP testing not configured" => $ldap_defined };
    foreach: GET $url [, username/password]; ok t_cmp($response->code, expected).
"""

import httpx
import pytest

from apache_pytest import need_module, t_cmp

# (url, username, password, expected-status)
CASES = [
    ("/modules/ldap/simple/", "", "", 401),
    ("/modules/ldap/simple/", "alpha", "badpass", 401),
    ("/modules/ldap/simple/", "alpha", "Alpha", 200),
    ("/modules/ldap/simple/", "gamma", "Gamma", 200),
    ("/modules/ldap/group/", "gamma", "Gamma", 401),
    ("/modules/ldap/group/", "delta", "Delta", 200),
    ("/modules/ldap/refer/", "alpha", "Alpha", 401),
    ("/modules/ldap/refer/", "beta", "Beta", 200),
    ("/modules/ldap/search/", "unchecked", "unchecked", 200),
]


def _ldap_configured(http):
    defines = http.vars("defines") or ""
    return "LDAP" in defines


@need_module("authnz_ldap")
@pytest.mark.parametrize("url,username,password,expected", CASES)
def test_ldap(http, url, username, password, expected):
    if not _ldap_configured(http):
        pytest.skip("LDAP testing not configured (run with --defines LDAP)")
    if username:
        r = http.GET(url, auth=httpx.BasicAuth(username, password))
    else:
        r = http.GET(url)
    creds = f"{username}/{password}" if username else "no credentials"
    assert t_cmp(r.status_code, expected), f"test for {url} with {creds}"
