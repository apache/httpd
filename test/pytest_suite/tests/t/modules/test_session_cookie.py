"""Translated from t/modules/session_cookie.t -- mod_session_cookie.

GET an error (404) and a normal (200) session_cookie URL. On httpd >= 2.5.0
also assert the Set-Cookie header is not duplicated (PR 60910).

Perl original used ``need_module 'session_cookie'``.
"""

from apache_pytest import need_min_apache_version, need_module, t_cmp


@need_module("session_cookie")
def test_session_cookie_404(http):
    r = http.GET("/modules/session_cookie/test404")
    assert t_cmp(r.status_code, 404)

    # PR 60910: Set-Cookie not duplicated in error response.
    if http.have_min_apache_version("2.5.0"):
        cookies = r.headers.get_list("Set-Cookie")
        assert t_cmp(len(cookies), 1), \
            "Set-Cookie header not duplicated in error response (404)."


@need_module("session_cookie")
def test_session_cookie_200(http):
    r = http.GET("/modules/session_cookie/test")
    assert t_cmp(r.status_code, 200)

    # PR 60910: Set-Cookie not duplicated in successful response.
    if http.have_min_apache_version("2.5.0"):
        cookies = r.headers.get_list("Set-Cookie")
        assert t_cmp(len(cookies), 1), \
            "Set-Cookie header not duplicated in successful response (200)."
