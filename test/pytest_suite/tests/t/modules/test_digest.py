r"""Translated from t/modules/digest.t -- mod_auth_digest query-string handling.

After confirming normal digest auth works, the test captures the generated
``Authorization`` header and replays it (verbatim and mangled) against the same
URL with/without the query string, verifying mod_auth_digest's query-string
validation (400 on mismatch). Then a set of MSIE behaviours via an ``X-Browser:
MSIE`` header (the AuthDigestEnableQueryStringHack path, removed in >= 2.5).

httpx's ``DigestAuth`` computes the digest response per request; we capture the
header from the response's request object to replay manually.

Perl original:
    plan tests => 13, need need_lwp, need_module('mod_auth_digest'),
        need_min_apache_version('2.0.51');
"""

import os

import httpx
import pytest

from apache_pytest import need_min_apache_version, need_module, t_cmp

URL = "/digest/index.html"
QUERY = "try=til%7Ede"

REALM_FILE_CONTENT = (
    "# user1/password1\n"
    "user1:realm1:4b5df5ee44449d6b5fbf026a7756e6ee\n"
)


def _write_realm(http):
    path = os.path.join(http.vars("serverroot"), "realm1")
    with open(path, "w") as f:
        f.write(REALM_FILE_CONTENT)


def _digest(user="user1", password="password1"):
    return httpx.DigestAuth(user, password)


@need_module("auth_digest")
@need_min_apache_version("2.0.51")
def test_digest(http):
    _write_realm(http)

    # no user to authenticate
    r = http.GET(URL)
    assert t_cmp(r.status_code, 401), "no user to authenticate"

    # bad pass
    r = http.GET(URL, auth=_digest("user1", "foo"))
    assert t_cmp(r.status_code, 401), "user1:foo not found"

    # authenticated
    r = http.GET(URL, auth=_digest())
    assert t_cmp(r.status_code, 200), "user1:password1 found"
    no_query_auth = r.request.headers.get("authorization")

    # add a query string
    r = http.GET(f"{URL}?{QUERY}", auth=_digest())
    assert t_cmp(r.status_code, 200), "user1:password1 with query string found"
    query_auth = r.request.headers.get("authorization")

    # replay the auth header ourselves
    r = http.GET(f"{URL}?{QUERY}", headers={"Authorization": query_auth})
    assert t_cmp(r.status_code, 200), "manual Authorization header query string"

    # remove the query string from the uri inside the header -- bang!
    noquery = query_auth.replace(QUERY, "")
    r = http.GET(f"{URL}?{QUERY}", headers={"Authorization": noquery})
    assert t_cmp(r.status_code, 400), \
        "manual Authorization with no query string in header"

    # change the query string in the header
    bad_query = query_auth.replace(QUERY, "something=else")
    r = http.GET(f"{URL}?{QUERY}", headers={"Authorization": bad_query})
    assert t_cmp(r.status_code, 400), \
        "manual Authorization header with mismatched query string"

    # another mismatch: header has query but uri doesn't
    r = http.GET(URL, headers={"Authorization": query_auth})
    assert t_cmp(r.status_code, 400), \
        "manual Authorization header with mismatched query string"

    # --- MSIE tests ---
    if http.have_min_apache_version("2.5.0"):
        pytest.skip("'AuthDigestEnableQueryStringHack' removed in r1703305")

    # fake current MSIE behavior - works as of 2.0.51
    r = http.GET(f"{URL}?{QUERY}",
                 headers={"Authorization": no_query_auth, "X-Browser": "MSIE"})
    assert t_cmp(r.status_code, 200), \
        "manual Authorization with no query string in header + MSIE"

    # pretend MSIE fixed itself
    r = http.GET(f"{URL}?{QUERY}", auth=_digest(), headers={"X-Browser": "MSIE"})
    assert t_cmp(r.status_code, 200), "a compliant response coming from MSIE"

    # this still bombs
    r = http.GET(f"{URL}?{QUERY}",
                 headers={"Authorization": bad_query, "X-Browser": "MSIE"})
    assert t_cmp(r.status_code, 400), \
        "manual Authorization header with mismatched query string + MSIE"

    # as does this
    r = http.GET(URL, headers={"Authorization": query_auth, "X-Browser": "MSIE"})
    assert t_cmp(r.status_code, 400), \
        "manual Authorization header with mismatched query string + MSIE"

    # no hack required
    r = http.GET(URL, auth=_digest(), headers={"X-Browser": "MSIE"})
    assert t_cmp(r.status_code, 200), "no query string + MSIE"
