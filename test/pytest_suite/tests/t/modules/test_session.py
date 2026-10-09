"""Translated from t/modules/session.t -- mod_session.

Exercises the Session directive, the optional encode/decode hooks,
SessionEnv/SessionHeader, SessionMaxAge expiry, SessionExpiryUpdateInterval
(2.4.41+) and SessionInclude/Exclude. Each check verifies the response code,
the X-Test-Session header (session data, with expiry stripped/validated),
X-Test-Session-Dirty, and the body.

Perl original used ``need need_module('session'),
need_min_apache_version('2.3.0')`` and a ``todo`` list of known-failing test
numbers (PR 58171/56052, and pre-2.4.41 backport PRs). The Python port does not
reproduce the exact todo-number bookkeeping; the substantive assertions are
preserved.
"""

import re
import time
import warnings

import pytest

from apache_pytest import need_min_apache_version, need_module, t_cmp

APR_TIME_PER_SEC = 1000000


def _expiry_from_seconds(seconds):
    # APR time is microseconds; append zeros to avoid 32-bit overflow (as Perl).
    return str(seconds) + "0" * (len(str(APR_TIME_PER_SEC)) - 1)


def _check(cond, msg, todo):
    """Assert ``cond``, but tolerate failure for Perl-``todo`` subtests.

    The original session.t lists certain subtest checks in its ``todo`` array
    (PR 58171 "writable after decode failure", PR 56052 "writable after
    expired"): on an httpd without the relevant fix they fail, on a fixed build
    they pass, and either way the harness must not error. mod_session on trunk
    resets a session that fails to decode/expire *in place* (``memset`` --
    "preserve pointers to zz in load/save providers"), so a provider that
    memoizes the session in ``r->notes`` (the test_session C module does) still
    sees the reset and saves it; 2.4.x instead drops it (``zz = NULL``) and
    allocates a fresh one the provider never sees, so nothing is saved.

    Mirror Perl's ``todo``: when ``todo`` is set, downgrade a failed check to a
    warning and continue (``pytest.xfail`` would abort the rest of the test).
    """
    if cond:
        return
    if todo:
        warnings.warn(f"known TODO failure: {msg}", stacklevel=2)
    else:
        raise AssertionError(msg)


def _check_result(name, res, session=None, dirty=None, expiry=None,
                  response=None, todo=False):
    # Perl defaults via // : undef -> '(none)'/0/0/''.
    session = "(none)" if session is None else session
    dirty = 0 if dirty is None else dirty
    expiry = 0 if expiry is None else expiry
    response = "" if response is None else response

    assert t_cmp(res.status_code, 200), f"response code ({name})"

    # Distinguish an absent header (-> "(none)") from a present empty one ("").
    got_session = res.headers.get("X-Test-Session")
    got_session = "(none)" if got_session is None else got_session
    session_data = got_session

    m = re.match(r"^(?:(.+)&)?expiry=([0-9]+)(?:&(.*))?$", got_session, re.IGNORECASE)
    if m:
        got_expiry = m.group(2)[: -(len(str(APR_TIME_PER_SEC)) - 1)]
        _check(bool(expiry) and time.time() < int(got_expiry), f"expiry ({name})", todo)
        parts = [p for p in (m.group(1), m.group(3)) if p is not None]
        session_data = "&".join(parts)
    else:
        _check(not expiry, f"no expiry ({name})", todo)

    _check(t_cmp(session_data, session), f"session header ({name})", todo)
    got_dirty = res.headers.get("X-Test-Session-Dirty")
    got_dirty = 0 if got_dirty is None else got_dirty
    _check(t_cmp(got_dirty, dirty), f"session dirty ({name})", todo)
    body = res.text.rstrip("\r\n")
    _check(t_cmp(body, response), f"body ({name})", todo)
    return got_session


def _check_get(http, name, path, **kw):
    res = http.GET(f"/sessiontest{path}")
    return _check_result(name, res, **kw)


def _check_post(http, name, path, data, **kw):
    # LWP's POST defaults to application/x-www-form-urlencoded.
    res = http.POST(f"/sessiontest{path}", content=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    return _check_result(name, res, **kw)


SESSION = "test=value"
ENCODED_PREFIX = "TestEncoded:"
ENCODED_SESSION = ENCODED_PREFIX + SESSION
CREATE_SESSION = "action=set&name=test&value=value"
READ_SESSION = "action=get&name=test"


@need_module("session", "test_session")
@need_min_apache_version("2.3.0")
def test_session(http):
    # Session directive
    _check_post(http, "Cannot write session when off", "/", CREATE_SESSION)
    _check_get(http, "New empty session is not saved", "/on")

    # API optional functions
    _check_post(http, "Set session", "/on", CREATE_SESSION, session=SESSION, dirty=1)
    _check_post(http, "Get session", f"/on?{SESSION}", READ_SESSION,
                session=None, dirty=0, expiry=0, response="value")
    _check_post(http, "Delete session", f"/on?{SESSION}", "action=set&name=test",
                session="", dirty=1)
    _check_post(http, "Edit session", f"/on?{SESSION}",
                "action=set&name=test&value=", session="test=", dirty=1)

    # Encoding hooks
    _check_post(http, "Encode session", "/on/encode", CREATE_SESSION,
                session=ENCODED_SESSION, dirty=1)
    _check_post(http, "Decode session", f"/on/encode?{ENCODED_SESSION}",
                READ_SESSION, session=None, dirty=0, expiry=0, response="value")
    _check_get(http, "Custom decoder failure", f"/on/encode?{SESSION}")
    _check_get(http, "Identity decoder failure", "/on?&=test")
    # PR 58171 todo: only fixed on trunk (mod_session resets the undecodable
    # session in place); 2.4.x discards it, so nothing is saved here.
    _check_post(http, "Session writable after decode failure",
                f"/on/encode?{SESSION}", CREATE_SESSION,
                session=ENCODED_SESSION, dirty=1, todo=True)

    # SessionEnv directive - requires mod_include
    if http.have_module("include"):
        _check_result("SessionEnv Off",
                      http.GET(f"/modules/session/env.shtml?{SESSION}"),
                      session=None, dirty=0, expiry=0, response="(none)")
        _check_get(http, "SessionEnv On", f"/on/env/on/env.shtml?{SESSION}",
                   session=None, dirty=0, expiry=0, response=SESSION)

    # SessionHeader directive
    _check_result(
        "SessionHeader",
        http.GET(f"/sessiontest/on?{SESSION}&another=1",
                 headers={"X-Test-Session-Override": "another=5&last=7"}),
        session=f"{SESSION}&another=5&last=7", dirty=1)

    # SessionMaxAge directive
    future_expiry = _expiry_from_seconds(int(time.time()) + 200)

    _check_get(http, "SessionMaxAge adds expiry", f"/on/expire?{SESSION}",
               session=SESSION, dirty=0, expiry=1)
    _check_get(http, "Discard expired session", f"/on/expire?{SESSION}&expiry=1",
               session="", dirty=0, expiry=1)
    _check_get(http, "Keep non-expired session",
               f"/on/expire?{SESSION}&expiry={future_expiry}",
               session=SESSION, dirty=0, expiry=1)
    # PR 56052 todo: like the decode-failure case, only saved on a fixed build.
    _check_post(http, "Session writable after expired", "/on/expire?expiry=1",
                CREATE_SESSION, session=SESSION, dirty=1, expiry=1, todo=True)

    # SessionExpiryUpdateInterval directive - new in 2.4.41
    if http.have_module("version") and http.have_min_apache_version("2.4.41"):
        max_expiry = _expiry_from_seconds(int(time.time()) + 100)
        threshold_expiry = _expiry_from_seconds(int(time.time()) + 40)

        _check_get(http, "SessionExpiryUpdateInterval off by default",
                   f"/on/expire?{SESSION}&expiry={max_expiry}",
                   session=SESSION, dirty=0, expiry=1)
        _check_get(http, "SessionExpiryUpdateInterval skips save",
                   f"/on/expire/cache?{SESSION}&expiry={max_expiry}")
        _check_post(http, "Session readable when save skipped",
                    f"/on/expire/cache?{SESSION}&expiry={max_expiry}",
                    READ_SESSION, session=None, dirty=0, expiry=0, response="value")
        _check_post(http, "Dirty overrides SessionExpiryUpdateInterval",
                    f"/on/expire/cache?{SESSION}&expiry={max_expiry}",
                    CREATE_SESSION, session=SESSION, dirty=1, expiry=1)
        _check_get(http, "Old session always updates expiry",
                   f"/on/expire/cache?{SESSION}&expiry={threshold_expiry}",
                   session=SESSION, dirty=0, expiry=1)
        _check_get(http, "New empty session with expiry not saved",
                   "/on/expire/cache")
        _check_post(http, "Can create session with SessionExpiryUpdateInterval",
                    "/on/expire/cache", CREATE_SESSION,
                    session=SESSION, dirty=1, expiry=1)

    # SessionInclude/Exclude directives
    _check_post(http, "Cannot write session when not included",
                f"/on/include?{SESSION}", CREATE_SESSION)
    _check_post(http, "Can read session when included",
                f"/on/include/yes?{SESSION}", READ_SESSION,
                session=None, dirty=0, expiry=0, response="value")
    _check_post(http, "SessionExclude overrides SessionInclude",
                f"/on/include/yes/no?{SESSION}", CREATE_SESSION)
