"""A backend response line without a colon must be named in the error log,
not the last line of the output read after it (PR 69916).
"""

import re

import pytest

from pyhttpd.conf import HttpdConf
from .env import TCPFaker


class _ScgiFaker(TCPFaker):

    @staticmethod
    def status_line(data):
        # an HTTP status line is not a valid CGI response header
        return (b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"\r\n"
                b"abcdefg")


class TestProxyScgiBadHeader:

    @pytest.fixture(scope='class')
    @classmethod
    def _class_scope(cls, env):
        env.require(env.has_shared_module("proxy_scgi"), "mod_proxy_scgi not available",
                    dep="mod_proxy_scgi",
                    detected=f"no mod_proxy_scgi.so in {env.libexec_dir}")
        faker = _ScgiFaker("127.0.0.1", env.http_port2)
        faker._make_response = _ScgiFaker.status_line
        faker.start()
        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port)
        conf.add([
            f"ProxyPass / scgi://127.0.0.1:{env.http_port2}/",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield faker
        faker.stop()

    # the error log names the malformed header line, not the response body
    def test_proxy_12_01(self, env, _class_scope):
        r = env.curl_get(env.mkurl("http", "test1", "/"))
        assert r.response["status"] == 500
        bad = r".*malformed header from script .*: Bad header: HTTP/1\.1 200 OK.*"
        body = r".*Bad header: abcdefg.*"
        try:
            found = env.httpd_error_log.scan_recent(re.compile(bad), timeout=2)
        except TimeoutError:
            found = False
        try:
            wrong = env.httpd_error_log.scan_recent(re.compile(body), timeout=0)
        except TimeoutError:
            wrong = False
        env.httpd_error_log.ignore_recent(
            lognos=["AH00860"],  # error reading response headers
            matches=[r".*malformed header from script .*"])
        assert found
        assert not wrong
