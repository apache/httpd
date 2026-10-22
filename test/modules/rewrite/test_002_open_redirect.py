import os
import re

import pytest

from pyhttpd.conf import HttpdConf


class TestRewriteOpenRedirect:
    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        rhts_dir = os.path.join(doc_dir, "rhts")
        os.makedirs(rhts_dir, exist_ok=True)
        with open(os.path.join(rhts_dir, "index.html"), "w") as f:
            f.write("test content\n")
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
        <Directory "{rhts_dir}">
            RewriteEngine On
            RewriteRule (.*)$ https://localhost$1
        </Directory>
        LogLevel rewrite:trace6
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_rewrite_002_01(self, env):
        url = env.mkurl("http", "test1", "/rhts/%0a.evilwebsite.com")
        r = env.curl_raw(url, options=['-v', '--max-redirs', '0'])
        if r.response is not None:
            assert r.response["status"] != 301 and \
                r.response["status"] != 302, \
                f"Should not redirect, got {r.response['status']}"
            if "location" in r.response.get("header", {}):
                loc = r.response["header"]["location"]
                assert "evilwebsite" not in loc, \
                    f"Redirect target contains attacker domain: {loc}"
        env.httpd_error_log.ignore_recent(
            matches=[r'.*rewrite:error.*', r'.*:error\].*',
                     r'.*:warn\].*'])


class TestRewriteEscapeSequences:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_dir = os.path.join(env.server_dir, "htdocs", "test1")
        rhts_dir = os.path.join(doc_dir, "rhts2")
        os.makedirs(rhts_dir, exist_ok=True)
        with open(os.path.join(rhts_dir, "index.html"), "w") as f:
            f.write("test content\n")
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": f"""
        <Directory "{rhts_dir}">
            RewriteEngine On
            RewriteRule "^path(.*)" "http://localhost:{env.http_port}/\\ttest/"
        </Directory>
        LogLevel rewrite:trace8
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_rewrite_002_02(self, env):
        start_pos = env.httpd_error_log.current_pos()
        url = env.mkurl("http", "test1", "/rhts2/path")
        env.curl_raw(url, options=['-v', '--max-redirs', '0'])
        found = env.httpd_error_log.wait_for(
            re.compile(r'.*escaping.*for redirect'),
            start_pos, timeout=5)
        env.httpd_error_log.ignore_recent(
            matches=[r'.*rewrite:error.*', r'.*:error\].*',
                     r'.*:warn\].*', r'.*:trace\d\].*'])
        assert found, \
            "Log should show 'escaping ... for redirect' for tab in target"
