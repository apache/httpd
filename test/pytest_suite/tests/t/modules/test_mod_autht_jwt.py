r"""Regression test for BZ 70275 -- mod_autht_jwt silently ignores the "exp"
(expiry) and "nbf" (not-before) claims unless their JSON value decoded to an
integer (``APR_JSON_LONG``).

check_token() in modules/aaa/mod_autht_jwt.c only accepted:

    if (kv->v->type == APR_JSON_LONG) { exp = kv->v->value.lnumber; exp_set = 1; }

RFC 7519 NumericDate is "a JSON numeric value" -- it does not have to be an
integer literal. A JSON number written with a decimal point or exponent (e.g.
``1700000000.0``) decodes to ``APR_JSON_DOUBLE``, not ``APR_JSON_LONG``, and a
number written as a quoted string decodes to ``APR_JSON_STRING``. Either way
the claim was silently dropped: ``exp_set``/``nbf_set`` stayed 0, so the whole
expiry/not-before check was skipped and the token was granted regardless of
whether it was actually expired or not yet valid.

This test builds real, validly-signed HS256 JWTs (no external `jwt` package)
and checks that: a float/string "exp" in the past is rejected, not silently
treated as "no expiry"; a float "nbf" in the future is rejected; and a float
"exp"/"nbf" that is actually still within its valid window is still accepted
(the fix must not reject well-formed RFC 7519 NumericDate values).
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


def _make_jwt_raw(claims_json: str) -> str:
    """Build a JWT from a literal claims JSON string (not a dict), so a claim
    value can be written as a bare float or a quoted numeric string exactly as
    an attacker-supplied or third-party-issued token would encode it."""
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(claims_json.encode())
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
def test_jwt_integer_exp_past_is_rejected(http):
    """Sanity check: an ordinary integer 'exp' in the past is rejected."""
    _skip_unless_functional(http)
    token = _make_jwt_raw(
        '{"sub":"alice","aud":"autht-jwt-test","exp":1000000000}'
    )
    r = http.GET("/autht-jwt-test/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401, (
        f"expected 401 for an expired integer 'exp', got {r.status_code}"
    )


@need_module("autht_jwt", "auth_bearer", "autht_core")
def test_jwt_float_exp_past_is_rejected(http):
    """BZ 70275: a float-encoded 'exp' in the past must still be rejected.
    Before the fix, kv->v->type == APR_JSON_DOUBLE (not APR_JSON_LONG) for a
    JSON number with a decimal point, so exp_set stayed 0 and the expiry
    check was skipped entirely -- the token was wrongly AUTHT_GRANTED."""
    _skip_unless_functional(http)
    token = _make_jwt_raw(
        '{"sub":"alice","aud":"autht-jwt-test","exp":1000000000.0}'
    )
    r = http.GET("/autht-jwt-test/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401, (
        "expired token accepted: a float 'exp' in the past was silently "
        f"ignored instead of enforced (got {r.status_code})"
    )


@need_module("autht_jwt", "auth_bearer", "autht_core")
def test_jwt_string_exp_past_is_rejected(http):
    """BZ 70275: a quoted-string 'exp' is not a valid RFC 7519 NumericDate at
    all and must cause rejection, not be silently ignored as if 'exp' were
    absent (which would make the token accepted with no expiry enforced)."""
    _skip_unless_functional(http)
    token = _make_jwt_raw(
        '{"sub":"alice","aud":"autht-jwt-test","exp":"1000000000"}'
    )
    r = http.GET("/autht-jwt-test/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401, (
        "malformed 'exp' accepted: a string-encoded NumericDate was silently "
        f"ignored instead of rejected (got {r.status_code})"
    )


@need_module("autht_jwt", "auth_bearer", "autht_core")
def test_jwt_float_nbf_future_is_rejected(http):
    """BZ 70275: a float-encoded 'nbf' in the future must still be enforced
    (not-yet-valid), the same failure mode as float 'exp' above."""
    _skip_unless_functional(http)
    token = _make_jwt_raw(
        '{"sub":"alice","aud":"autht-jwt-test","nbf":4000000000.0}'
    )
    r = http.GET("/autht-jwt-test/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401, (
        "not-yet-valid token accepted: a float 'nbf' in the future was "
        f"silently ignored instead of enforced (got {r.status_code})"
    )


@need_module("autht_jwt", "auth_bearer", "autht_core")
def test_jwt_float_exp_and_nbf_within_window_is_accepted(http):
    """The fix must not reject well-formed RFC 7519 NumericDate values: a
    float 'exp' in the future and a float 'nbf' in the past (i.e. the token
    IS currently valid) must still be accepted."""
    _skip_unless_functional(http)
    token = _make_jwt_raw(
        '{"sub":"alice","aud":"autht-jwt-test",'
        '"exp":4000000000.5,"nbf":1000000000.5}'
    )
    r = http.GET("/autht-jwt-test/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, (
        "a currently-valid token with float 'exp'/'nbf' NumericDate values "
        f"was wrongly rejected (got {r.status_code})"
    )


@need_module("autht_jwt", "auth_bearer", "autht_core")
def test_jwt_exp_of_exactly_two_to_the_63_is_rejected(http):
    """Boundary case: (double) APR_INT64_MAX is not exactly representable
    and rounds up to 2**63, one past the largest valid apr_int64_t. A
    float 'exp' of exactly 2**63 must be rejected as malformed rather than
    accepted into an out-of-range double-to-int64 cast (undefined
    behavior; confirmed with UBSan to silently wrap to INT64_MIN)."""
    _skip_unless_functional(http)
    token = _make_jwt_raw(
        '{"sub":"alice","aud":"autht-jwt-test","exp":9223372036854775808.0}'
    )
    r = http.GET("/autht-jwt-test/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401, (
        "an 'exp' of exactly 2**63 was accepted instead of rejected as an "
        f"out-of-range NumericDate (got {r.status_code})"
    )


@need_module("autht_jwt", "auth_bearer", "autht_core")
def test_jwt_exp_just_below_two_to_the_63_is_accepted(http):
    """The largest double strictly less than 2**63 (9223372036854774784.0,
    2**63 - 1024) is a valid, in-range NumericDate and must still be
    accepted -- the boundary fix must not reject values just under the
    cutoff, only the cutoff itself and above."""
    _skip_unless_functional(http)
    token = _make_jwt_raw(
        '{"sub":"alice","aud":"autht-jwt-test","exp":9223372036854774784.0}'
    )
    r = http.GET("/autht-jwt-test/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, (
        "a valid in-range 'exp' just below 2**63 was wrongly rejected "
        f"(got {r.status_code})"
    )


@need_module("autht_jwt", "auth_bearer", "autht_core")
def test_jwt_nbf_of_exactly_min_int64_is_accepted(http):
    """-2**63 (apr_int64_t's true minimum) IS exactly representable as a
    double with no rounding error, unlike the upper bound, so it must
    still be accepted at the lower boundary."""
    _skip_unless_functional(http)
    token = _make_jwt_raw(
        '{"sub":"alice","aud":"autht-jwt-test",'
        '"nbf":-9223372036854775808.0,"exp":9999999999.0}'
    )
    r = http.GET("/autht-jwt-test/", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, (
        "a valid 'nbf' of exactly -2**63 was wrongly rejected "
        f"(got {r.status_code})"
    )
