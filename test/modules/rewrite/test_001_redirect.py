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
    def test_rewrite_001_01(self, env):
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
    def test_rewrite_001_02(self, env):
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
