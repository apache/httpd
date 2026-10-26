import re
import pytest

from pyhttpd.conf import HttpdConf


class TestForwardProxySsrf:
    """NULL dereference or SSRF in forward proxy configurations via
    unix: prefix in request URI."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env)
        conf.start_vhost(domains=[env.d_forward], port=env.http_port)
        conf.add([
            "ProxyRequests On",
            "ProxyVia On",
            "LogLevel proxy:trace8",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    def test_proxy_008_01(self, env):
        """Forward proxy request with unix: prefix should not attempt
        to connect to a Unix Domain Socket (SSRF)."""
        start_pos = env.httpd_error_log.current_pos()
        url = f"unix:/tmp/test.sock|http://www.example.com/foo"
        env.curl_raw(url, options=[
            '-x', f'http://localhost:{env.http_port}',
            '--connect-timeout', '5', '--max-time', '10',
        ])
        found = env.httpd_error_log.wait_for(
            re.compile(r'.*attempt.*to.*connect.*to.*Unix.*'),
            start_pos, timeout=5)
        env.httpd_error_log.ignore_recent(
            lognos=["AH00898", "AH00961"],
            matches=[r'.*proxy:error.*', r'.*proxy_http:error.*',
                     r'.*:warn\].*', r'.*:error\].*'])
        assert not found, \
            "Forward proxy should not attempt Unix socket connection"


class TestProxyH2MalformedRequest:
    """Assertion failure in mod_proxy_http2 when a malformed raw request
    is proxied to an h2c backend with ProxyPreserveHost enabled."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            'base': f"""
        Listen {env.http_port + 1}
        ProxyPreserveHost On
        ProxyPass /testproxy h2c://localhost:{env.http_port + 1}/
        ProxyPassReverse /testproxy http://localhost:{env.http_port + 1}/
        <VirtualHost *:{env.http_port + 1}>
        </VirtualHost>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_proxy_008_02(self, env):
        """Malformed request through h2c proxy should produce a log
        message about HTTP/0.9 with no host line, not an assertion
        failure or crash."""
        start_pos = env.httpd_error_log.current_pos()
        r = env.curl_raw(f"http://localhost:{env.http_port}/testproxy/a\r\n",
                         options=[
                             '--connect-timeout', '5', '--max-time', '10',
                         ])
        crash_found = env.httpd_error_log.wait_for(
            re.compile(r'.*exit signal Segmentation fault.*|.*Assertion.*failed.*'),
            start_pos, timeout=5)
        env.httpd_error_log.ignore_recent(
            matches=[r'.*proxy:error.*', r'.*proxy_http2:error.*',
                     r'.*:warn\].*', r'.*:error\].*',
                     r'.*HTTP/0.9 request.*'])
        assert not crash_found, \
            "Malformed h2c proxy request should not crash the server"


class TestProxyErrorPageXss:
    """Limited cross-site scripting in mod_proxy error page. When a proxy
    backend is unreachable, the error page should not reflect the request
    URI unescaped."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            'base': f"""
        ProxyPass / http://localhost:19999/
        ProxyPassReverse / http://localhost:19999/
        LogLevel proxy:trace1
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_proxy_008_03(self, env):
        """Proxy error page should not echo the request URI unescaped."""
        request_uri = "http:%2f%2fgoogle.org"
        url = env.mkurl("http", "test1", f"/{request_uri}")
        r = env.curl_get(url)
        assert r.response["status"] in [404, 502, 503]
        body = r.response["body"].decode() if isinstance(
            r.response["body"], bytes) else r.response["body"]
        assert request_uri not in body, \
            "Request URI should not appear unescaped in proxy error page"
        env.httpd_error_log.ignore_recent(
            matches=[r'.*proxy:error.*', r'.*proxy_http:error.*',
                     r'.*:error\].*'])
