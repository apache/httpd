import os
import re

import pytest

from pyhttpd.conf import HttpdConf


class TestRewriteRedirect:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env)
        # VirtualHost that strips "www." prefix and redirects
        conf.start_vhost(
            domains=[f"www.rewrite.{env.http_tld}"],
            port=env.http_port,
            doc_root="htdocs",
            with_ssl=False,
        )
        conf.add([
            "RewriteEngine On",
            r"RewriteCond %{HTTP_HOST} ^www\.(.+)",
            r"RewriteRule ^ http://%1%{REQUEST_URI} [R=301,L]",
        ])
        conf.end_vhost()
        # VirtualHost that prepends "www." and redirects
        conf.start_vhost(
            domains=[f"rewrite.{env.http_tld}"],
            port=env.http_port,
            doc_root="htdocs",
            with_ssl=False,
        )
        conf.add([
            "RewriteEngine On",
            r"RewriteCond %{HTTP_HOST} !^www\.",
            r"RewriteRule ^ http://www.%{HTTP_HOST}%{REQUEST_URI} [R=301,L]",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield

    # Redirect www.domain -> non-www domain
    def test_rewrite_001_01_domain_to_non_domain(self, env):
        url = f"http://www.rewrite.{env.http_tld}:{env.http_port}/"
        r = env.curl_raw(url, options=[])
        assert r.exit_code == 0, f"curl failed: {r}"
        assert r.response["status"] == 301
        location = r.response["header"]["location"]
        expected = f"http://rewrite.{env.http_tld}:{env.http_port}/"
        assert location == expected, (
            f"expected redirect to '{expected}', got '{location}'"
        )

    # Redirect non-www domain -> www.domain
    def test_rewrite_001_02_non_domain_to_domain(self, env):
        url = f"http://rewrite.{env.http_tld}:{env.http_port}/"
        r = env.curl_raw(url, options=[])
        assert r.exit_code == 0, f"curl failed: {r}"
        assert r.response["status"] == 301
        location = r.response["header"]["location"]
        expected = f"http://www.rewrite.{env.http_tld}:{env.http_port}/"
        assert location == expected, (
            f"expected redirect to '{expected}', "
            f"got '{location}'"
        )

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

    def test_rewrite_002_01_redirect_bad(self, env):
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

    def test_rewrite_002_02_escape_directs(self, env):
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
