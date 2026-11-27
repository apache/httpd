r"""Regression test for BZ 69946 -- mod_autht_jwt authentication bypass via
claim-name prefix matching.

``check_token()`` in modules/aaa/mod_autht_jwt.c identified the ``aud``,
``sub``, ``exp`` and ``nbf`` claims with:

    strncmp("aud", kv->k->value.string.p, kv->k->value.string.len)

``strncmp(a, b, n)`` only compares the first ``n`` bytes. Since ``n`` here is
the *actual* claim-name length (not the length of the literal), a claim
whose name is a proper prefix of "aud" (e.g. "a" or "au") satisfies this
check and is treated as if it were the real "aud" claim. A JWT that omits
"aud" entirely but carries such a short claim with the expected AuthName
value then passes the audience check that is supposed to confirm the token
was issued for this specific location.

This test builds real HS256 JWTs (no external `jwt` package -- the standard
library's hmac/hashlib/base64 are enough) and checks that a token exploiting
the prefix match is rejected, while a token using the real "aud" claim name
still works.
"""

import base64
import hashlib
import hmac
import json

import pytest

from apache_pytest import need_module

# Kept in sync with apache_pytest.config.TestConfig.AUTHT_JWT_SECRET, which
# writes this value to the file AuthtJwtVerify loads before httpd starts.
SECRET = b"bz69946-test-secret-do-not-use-in-prod"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_jwt(claims: dict) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(SECRET, signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


def _skip_unless_functional(http):
    """need_module() only checks that mod_autht_jwt.so is loaded, not that it
    was built with apr_jose/JWT support (BZ 70276/70277): a stub build
    registers the same module name but neither the AuthtJwtVerify directive
    nor the "jwt" Autht provider, so <IfDirective AuthtJwtVerify> in
    autht_jwt.conf.in omits the /autht-jwt-test/ Location entirely. On such a
    build this request hits a plain, unauthenticated static file (200); on a
    functional build AuthType bearer with no Authorization header is
    rejected (401). Skip explicitly rather than failing on the stub build's
    404/200, and never silently pass tests that never actually exercised the
    module."""
    r = http.GET("/autht-jwt-test/")
    if r.status_code != 401:
        pytest.skip(
            "mod_autht_jwt built without JOSE/JWT support "
            f"(stub build, BZ 70276/70277; got {r.status_code} with no Authorization header)"
        )


@need_module("autht_jwt", "auth_bearer", "autht_core")
def test_jwt_aud_exact_match_is_accepted(http):
    """Sanity check: a token with the real 'aud' claim is accepted."""
    _skip_unless_functional(http)
    token = _make_jwt({"aud": "autht-jwt-test", "sub": "alice"})
    r = http.GET("/autht-jwt-test/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, (
        f"expected 200 for a valid 'aud' claim, got {r.status_code}"
    )


@need_module("autht_jwt", "auth_bearer", "autht_core")
def test_jwt_missing_aud_is_rejected(http):
    """Sanity check: a token with no audience-like claim at all is rejected."""
    _skip_unless_functional(http)
    token = _make_jwt({"foo": "bar", "sub": "alice"})
    r = http.GET("/autht-jwt-test/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401, (
        f"expected 401 with no 'aud' claim present, got {r.status_code}"
    )


@need_module("autht_jwt", "auth_bearer", "autht_core")
def test_jwt_aud_prefix_bypass_is_rejected(http):
    """BZ 69946: a claim whose name is a prefix of 'aud' ('au') must NOT be
    treated as the 'aud' claim. Before the fix this token is wrongly
    AUTHT_GRANTED (200); after the fix it must be AUTHT_MISMATCH (401).

    'sub' is required here: Require valid-user needs r->user, which
    check_token() only sets when 'sub' is present. Without it this test
    would get 401 regardless of the aud bug and prove nothing."""
    _skip_unless_functional(http)
    token = _make_jwt({"au": "autht-jwt-test", "sub": "alice"})
    r = http.GET("/autht-jwt-test/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401, (
        "authentication bypass: a claim named 'au' (a prefix of 'aud') with "
        f"the correct AuthName value was accepted as 'aud' (got {r.status_code})"
    )


@need_module("autht_jwt", "auth_bearer", "autht_core")
def test_jwt_aud_single_char_prefix_bypass_is_rejected(http):
    """Same bypass with the shortest possible prefix, 'a'."""
    _skip_unless_functional(http)
    token = _make_jwt({"a": "autht-jwt-test", "sub": "alice"})
    r = http.GET("/autht-jwt-test/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401, (
        "authentication bypass: a claim named 'a' (a prefix of 'aud') with "
        f"the correct AuthName value was accepted as 'aud' (got {r.status_code})"
    )
