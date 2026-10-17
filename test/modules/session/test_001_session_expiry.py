import os
import re
import time
import pytest

from pyhttpd.conf import HttpdConf


class TestSessionExpiry:
    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        cgi_dir = os.path.join(env.server_dir, "htdocs", "test1", "cgi")
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
        <Directory "{cgi_dir}">
            Options +ExecCGI
            AddHandler cgi-script .py
        </Directory>
        <Location />
            Session On
            SessionEnv On
            SessionCookieName session path=/
            SessionHeader X-Replace-Session
            SessionMaxAge 5
        </Location>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_session_001_01(self, env):
        unix_time = int(time.time())
        url = env.mkurl("http", "test1", "/cgi/session.py")
        r = env.curl_raw(url, options=[
            '--cookie', f'session=key1=foo&key3=bar&expiry={unix_time}',
        ])
        assert r.exit_code == 0
        body = r.stdout if r.stdout else ""
        assert "HTTP_SESSION=expiry=" in body, \
            f"Expected expired session output, got: {body}"
        assert "HTTP_SESSION=key1=foo&key3=bar&expiry=" not in body, \
            "Expired session data should not pass through to CGI"

    def test_session_001_02(self, env):
        start_pos = env.httpd_error_log.current_pos()
        unix_time = int(time.time())
        url = env.mkurl("http", "test1", "/cgi/session.py")
        r = env.curl_raw(url, options=[
            '-j', '--cookie', f'session=key1=foo&=&expiry={unix_time}',
        ])
        assert r.exit_code == 0
        crash = env.httpd_error_log.wait_for(
            re.compile(r'.*exit signal Segmentation fault.*'),
            start_pos, timeout=3)
        assert not crash, "Empty session key should not cause a segfault"
        body = r.stdout if r.stdout else ""
        assert "HTTP_SESSION=expiry=" in body, \
            f"Expected session output, got: {body}"
        assert "HTTP_SESSION=key1=foo&expiry=" not in body, \
            "Session data with empty key should not leak through"
