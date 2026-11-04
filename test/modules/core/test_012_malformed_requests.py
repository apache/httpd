import os
import re
import pytest

from pyhttpd.conf import HttpdConf

class TestNull:
    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env)
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_core_012_01(self, env):
        url = f"https://localhost:{env.http_port}/"
        env.curl_raw(url, options=[
            '--connect-timeout', '5', '--max-time', '10', '-k',
        ])

class TestBadRequest:
    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            'base': """
        KeepAlive On
        Redirect 301 /2bad /destination
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_core_012_02(self, env):
        url = env.mkurl("http", "test1", "/2bad")
        r = env.curl_raw(url, options=[
            '-H', 'Content-Length: 1', '-v',
            '--connect-timeout', '5', '--max-time', '10',
        ])
        if r.response is not None:
            assert r.response["status"] != 301, \
                "Should not redirect if request body not fully consumed"
            assert r.response["status"] in [400, 408], \
                f"Expected 400 or 408, got {r.response['status']}"
        else:
            assert "Closing connection" in r.stderr or \
                "Connection reset" in r.stderr or \
                r.exit_code != 0, \
                "Connection should be closed, not left intact"
            assert "HTTP/1.1 301" not in r.stderr, \
                "Should not redirect if request body not fully consumed"
        env.httpd_error_log.ignore_recent(
            lognos=["AH10390"],
            matches=[r'.*:error\].*', r'.*:warn\].*'])


class TestBadOptions:
    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        htdocs = os.path.join(env.server_dir, "htdocs", "test1")
        ob_dir = os.path.join(htdocs, "badoption")
        os.makedirs(ob_dir, exist_ok=True)
        with open(os.path.join(ob_dir, ".htaccess"), "w") as f:
            f.write("<Limit INVALID XXX FOO BAR BAZ>\n</Limit>\n")
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
        <Directory "{ob_dir}">
            AllowOverride Limit
        </Directory>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_core_012_03(self, env):
        """OPTIONS request to directory with invalid Limit directive should
        return 500 and log a configuration error, not leak memory."""
        url = env.mkurl("http", "test1", "/badoption/")
        r = env.curl_raw(url, options=['-X', 'OPTIONS', '-v'])
        assert r.response is not None
        assert r.response["status"] == 500
        env.httpd_error_log.ignore_recent(
            matches=[r'.*Could not register method.*',
                     r'.*core:error.*'])
