r"""Translated from t/modules/aaa.t -- authz by user id / envvar across AuthTypes.

For basic and digest auth: GET an authz-protected page with no creds (401), bad
creds (401), good creds (200), authz-by-env X-Allowed (200, no auth headers),
and authz-by-env on a missing page (404, no auth headers). For form auth:
exercises the redirect-to-login / login-POST / authorized flow with a cookie
jar. Finally checks AuthzSendForbiddenOnFailure (401 vs 403) on >= 2.3.11.

Perl original: plan tests => ..., need need_lwp, mod_authn_core, mod_authz_core,
mod_authn_file, mod_authz_host, need_min_apache_version('2.3.7').
"""

import os

import httpx
import pytest

from apache_pytest import need_min_apache_version, need_module, t_cmp

AUTH_HEADERS = ["WWW-Authenticate", "Authentication-Info", "Location"]

HTPASSWD_FILES = {
    "realm2": "# udigest/pdigest\nudigest:realm2:bccffb0d42943019acfbebf2039b8a3a\n",
    "basic1": "# ubasic:pbasic\nubasic:$apr1$opONH1Fj$dX0sZdZ0rRWEk0Wj8y.Qv1\n",
    "form1": "# uform:pform\nuform:$apr1$BzhDZ03D$U598kbSXGy/R7OhYXu.JJ0\n",
}


def _write_htpasswd(http):
    root = http.vars("serverroot")
    for name, content in HTPASSWD_FILES.items():
        with open(os.path.join(root, name), "w") as f:
            f.write(content)


def _check_no_auth_headers(r):
    for h in AUTH_HEADERS:
        assert r.headers.get(h) is None, f"{r.status_code} response should have no {h}"


@need_module("authn_core", "authz_core", "authn_file", "authz_host")
@need_min_apache_version("2.3.7")
@pytest.mark.parametrize("type_", ["basic", "digest"])
def test_basic_digest(http, type_):
    if not http.have_module(f"auth_{type_}"):
        pytest.skip(f"mod_auth_{type_} not available")
    _write_htpasswd(http)
    url = f"/authz/{type_}/index.html"

    if type_ == "basic":
        good = httpx.BasicAuth(f"u{type_}", f"p{type_}")
        bad = httpx.BasicAuth(f"u{type_}", "foo")
    else:
        good = httpx.DigestAuth(f"u{type_}", f"p{type_}")
        bad = httpx.DigestAuth(f"u{type_}", "foo")

    r = http.GET(url)
    assert t_cmp(r.status_code, 401), f"{type_}: no user to authenticate"

    r = http.GET(url, auth=bad)
    assert t_cmp(r.status_code, 401), f"{type_}: u{type_}:foo not found"

    r = http.GET(url, auth=good)
    assert t_cmp(r.status_code, 200), f"{type_}: u{type_}:p{type_} found"

    r = http.GET(url, headers={"X-Allowed": "yes"})
    assert t_cmp(r.status_code, 200), f"{type_}: authz by envvar"
    _check_no_auth_headers(r)

    r = http.GET(f"{url}.foo", headers={"X-Allowed": "yes"})
    assert t_cmp(r.status_code, 404), f"{type_}: not found"
    _check_no_auth_headers(r)


@need_module("authn_core", "authz_core", "authn_file", "authz_host")
@need_min_apache_version("2.3.7")
def test_form(http):
    if not http.have_module("auth_form"):
        pytest.skip("mod_auth_form not available")
    if not http.have_module("session_cookie"):
        pytest.skip("mod_auth_form tests require mod_session_cookie")
    _write_htpasswd(http)

    url = "/authz/form/index.html"
    login_url = "/authz/form/dologin.html"

    def loc_path(r):
        loc = r.headers.get("Location")
        if loc and loc.startswith("http"):
            # strip scheme://host
            idx = loc.find("/", loc.find("://") + 3)
            return loc[idx:] if idx != -1 else loc
        return loc

    base = http.base_url

    # access without user/env should redirect to login
    with httpx.Client(base_url=base, follow_redirects=False) as c:
        r = c.get(url)
        assert t_cmp(r.status_code, 302), "form: access without user/env redirects"
        loc = loc_path(r)
        assert t_cmp(loc, "/authz/login.html"), "form: redirect to login form"

    # bad pass
    with httpx.Client(base_url=base, follow_redirects=False) as c:
        r = c.post(login_url,
                   data={"httpd_username": "uform", "httpd_password": "foo"})
        assert t_cmp(r.status_code, 302), "form: wrong passwd redirects"
        assert t_cmp(loc_path(r), "/authz/login.html"), \
            "form: wrong passwd redirects to login form"
        r = c.get(url)
        assert t_cmp(r.status_code, 302), "form: wrong passwd should not allow access"

    # authenticated
    with httpx.Client(base_url=base, follow_redirects=False) as c:
        r = c.post(login_url,
                   data={"httpd_username": "uform", "httpd_password": "pform"})
        assert t_cmp(r.status_code, 302), "form: correct passwd redirects"
        assert t_cmp(loc_path(r), "/authz/form/"), \
            "form: correct passwd redirects to SuccessLocation"
        r = c.get(url)
        assert t_cmp(r.status_code, 200), "form: correct passwd did not allow access"

    # authorized by env
    with httpx.Client(base_url=base, follow_redirects=False) as c:
        r = c.get(url, headers={"X-Allowed": "yes"})
        assert t_cmp(r.status_code, 200), "form: authz by envvar"
        _check_no_auth_headers(r)

        r = c.get(f"{url}.foo", headers={"X-Allowed": "yes"})
        assert t_cmp(r.status_code, 404), "form: not found"
        _check_no_auth_headers(r)


@need_module("authn_core", "authz_core", "authn_file", "authz_host")
@need_min_apache_version("2.3.7")
def test_authz_send_forbidden(http):
    if not http.have_min_apache_version("2.3.11"):
        pytest.skip("AuthzSendForbiddenOnFailure requires httpd >= 2.3.11")
    _write_htpasswd(http)
    for want in (401, 403):
        r = http.GET(f"/authz/fail/{want}",
                     auth=httpx.BasicAuth("ubasic", "pbasic"))
        assert t_cmp(r.status_code, want), f"Expected code {want}, got {r.status_code}"
