import os
import re

import pytest

from pyhttpd.conf import HttpdConf

# RFC 6265, section 4.1.1: cookie-pair *( ";" SP cookie-av )
SET_COOKIE = re.compile(
    r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+="
    r"(?:[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*"
    r"|\"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*\")"
    r"(?:; [\x21-\x3a\x3c-\x7e][\x20-\x3a\x3c-\x7e]*)*")


class TestSetCookieSyntax:
    """The session cookie is written with the attribute separator of
    RFC 6265, whatever separators the configured attributes use."""

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        cgi_dir = os.path.join(env.server_dir, "htdocs", "test1", "cgi")
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
        <Directory "{cgi_dir}">
            Options +ExecCGI
            AddHandler cgi-script .py
        </Directory>
        <Location /cgi>
            Session On
            SessionHeader X-Replace-Session
            SessionMaxAge 60
            SessionCookieName session path=/;HttpOnly ;  ;
        </Location>
        <Location /default>
            Session On
            SessionHeader X-Replace-Session
            SessionCookieName session
        </Location>
        <Location /clear>
            Session On
            SessionHeader X-Replace-Session
            SessionCookieName session path=/;HttpOnly ;
        </Location>
        <Location /cookie2>
            Session On
            SessionHeader X-Replace-Session
            SessionCookieName2 session2 path=/;;HttpOnly
        </Location>
        Alias /default/ "{cgi_dir}/"
        Alias /clear/ "{cgi_dir}/"
        Alias /cookie2/ "{cgi_dir}/"
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def _set_cookie(self, env, path, name="session", header="set-cookie"):
        url = env.mkurl("http", "test1", path)
        r = env.curl_raw(url, options=["--cookie", f"{name}=key1=foo"])
        assert r.exit_code == 0
        assert r.response["status"] == 200, f"{r.stdout}"
        cookies = r.response["header"].get(header)
        assert cookies, f"no Set-Cookie: {r.response['header']}"
        return cookies

    def test_session_003_01_configured_attributes(self, env):
        cookie = self._set_cookie(env, "/cgi/session.py")
        assert SET_COOKIE.fullmatch(cookie), cookie
        assert cookie.endswith("; Max-Age=60; path=/; HttpOnly"), cookie

    def test_session_003_02_default_attributes(self, env):
        cookie = self._set_cookie(env, "/default/session.py")
        assert SET_COOKIE.fullmatch(cookie), cookie
        assert cookie.endswith("; HttpOnly; Secure; Version=1"), cookie

    def test_session_003_03_removal(self, env):
        cookie = self._set_cookie(env, "/default/session-clear.py")
        assert SET_COOKIE.fullmatch(cookie), cookie
        assert cookie == "session=; Max-Age=0", cookie

    def test_session_003_04_removal_with_attributes(self, env):
        cookie = self._set_cookie(env, "/clear/session-clear.py")
        assert SET_COOKIE.fullmatch(cookie), cookie
        assert cookie == "session=; Max-Age=0; path=/; HttpOnly", cookie

    def test_session_003_05_set_cookie2(self, env):
        cookie = self._set_cookie(env, "/cookie2/session.py",
                                  name="session2", header="set-cookie2")
        assert SET_COOKIE.fullmatch(cookie), cookie
        assert cookie.endswith("; path=/; HttpOnly"), cookie
