import base64
import hashlib
import os
import re

import pytest

from pyhttpd.conf import HttpdConf


class TestAuthFormCookieRemove:
    """A login through mod_auth_form sets the session cookie even when
    SessionCookieRemove hides that cookie from the request."""

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        for mod in ("auth_form", "request"):
            env.require(env.has_shared_module(mod), f"mod_{mod} is not built",
                        dep=f"mod_{mod}")
        docs = os.path.join(env.server_dir, "htdocs", "test1")
        for d in ("form-remove", "form-keep", "redir"):
            os.makedirs(os.path.join(docs, d), exist_ok=True)
            with open(os.path.join(docs, d, "index.html"), "w") as fd:
                fd.write("ok\n")
        passwd = os.path.join(env.server_dir, "form.passwd")
        sha = base64.b64encode(hashlib.sha1(b"secret").digest()).decode()
        with open(passwd, "w") as fd:
            fd.write(f"user:{{SHA}}{sha}\n")
        cgi_dir = os.path.join(docs, "cgi")
        form = f"""
            AuthType form
            AuthName form
            AuthFormProvider file
            AuthUserFile {passwd}
            AuthFormLoginSuccessLocation /index.html
            Require valid-user
            Session On
            SessionCookieName session path=/
"""
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
        <Directory "{cgi_dir}">
            Options +ExecCGI
            AddHandler cgi-script .py
            Session On
            SessionCookieName session path=/
            SessionCookieRemove On
        </Directory>
        <Location /form-remove>{form}
            SessionCookieRemove On
        </Location>
        <Location /form-keep>{form}
        </Location>
        <Location /redir>
            Session On
            SessionCookieName session path=/
            ErrorDocument 404 /cgi/session.py
        </Location>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def _login(self, env, path):
        url = env.mkurl("http", "test1", path)
        return env.curl_raw(url, options=[
            "--data", "httpd_username=user&httpd_password=secret",
        ])

    @pytest.mark.parametrize("path", ["/form-keep/", "/form-remove/"])
    def test_session_002_01_login_sets_cookie(self, env, path):
        r = self._login(env, path)
        assert r.exit_code == 0
        assert r.response["status"] == 302, f"{r.stdout}"
        cookies = [v for k, v in r.response["header"].items()
                   if k.lower() == "set-cookie"]
        assert any(re.match(r"session=.*form-user=user", c)
                   for c in cookies), f"no session cookie: {r.response['header']}"

    def test_session_002_02_removed_after_internal_redirect(self, env):
        # the session is loaded where it is kept, then the internal
        # redirect lands where it must be removed (CVE-2026-47360)
        url = env.mkurl("http", "test1", "/redir/missing")
        r = env.curl_raw(url, options=[
            "--cookie", "session=key1=foo; other=bar",
        ])
        assert r.exit_code == 0
        assert r.response["status"] == 404
        cookie = [line for line in r.stdout.splitlines()
                  if line.startswith("HTTP_COOKIE=")]
        assert cookie, r.stdout
        assert cookie[0].split("=", 1)[1].strip() == "other=bar", cookie[0]
