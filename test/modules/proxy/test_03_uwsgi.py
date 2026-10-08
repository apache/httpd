"""
Tests for mod_proxy_uwsgi fix.

Per PEP 3333, WSGI applications must not generate hop-by-hop
headers. Remove any such headers received from the backend.
"""

import re

import pytest

from pyhttpd.conf import HttpdConf
from .uwsgi_faker import UwsgiFaker
from .env import TCPFaker


UWSGI_PORT = 5200

class _UWSGIFaker(TCPFaker):

    @staticmethod
    def hello(data):
        body = b"Hello"
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            + body
        )

    @staticmethod
    def empty_header(data):
        body = b"Hello"
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"X-Empty:\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            + body
        )

class TestProxyUwsgi:

    @pytest.fixture(scope="function")
    def _proxy_uwsgi_setup(self, env):
        faker = UwsgiFaker(port=UWSGI_PORT)
        faker.start()

        conf = HttpdConf(env)
        conf.start_vhost(
            domains=[env.d_reverse],
            port=env.http_port,
            with_ssl=False,
        )
        conf.add([
            "LogLevel proxy_uwsgi:debug",
            f"ProxyPass / uwsgi://127.0.0.1:{UWSGI_PORT}/",
            "LogLevel trace4",
        ])
        conf.end_vhost()
        conf.install()

        assert env.apache_restart() == 0

        yield

        faker.stop()

    @pytest.fixture(scope='function')
    def _class_scope(self, env):
        if not env.has_shared_module("proxy_uwsgi"):
            pytest.skip("mod_proxy_uwsgi not available")
        faker = _UWSGIFaker("127.0.0.1", env.http_port2)
        faker.start()
        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port)
        conf.add([
            f"ProxyPass / uwsgi://127.0.0.1:{env.http_port2}/",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield faker
        faker.stop()

    def test_proxy_03_001(self, env, _proxy_uwsgi_setup):
        """uWSGI backend response is forwarded correctly."""
        r = env.curl_get(
            f"http://{env.d_reverse}:{env.http_port}/",
            5,
        )
        assert r.response["status"] == 200
        assert r.json["host"] == "uwsgi-faker"

    def test_proxy_03_002(self, env, _proxy_uwsgi_setup):
        """No Transfer-Encoding header reaches the client."""
        r = env.curl_get(
            f"http://{env.d_reverse}:{env.http_port}/",
            5,
        )
        assert r.response["status"] == 200
        assert "transfer-encoding" not in r.response["header"]

    def test_proxy_03_003(self, env, _proxy_uwsgi_setup):
        """Transfer-Encoding is stripped by mod_proxy_uwsgi."""
        r = env.curl_get(
            f"http://{env.d_reverse}:{env.http_port}/?te=1",
            5, 
        )

        print("response =", r.response)
        print("stderr   =", getattr(r, "stderr", None))
        print("stdout   =", getattr(r, "stdout", None))
        print("exitcode =", getattr(r, "exit_code", None))
        print("json     =", getattr(r, "json", None))

        assert r.response is not None
        assert r.response["status"] == 200
        assert "transfer-encoding" not in r.response["header"]

        assert r.json["host"] == "uwsgi-faker"

        assert env.httpd_error_log.scan_recent(
            re.compile(
                r".*uwsgi: removing hop-by-hop header 'Transfer-Encoding'"
            )
        )

    # verify uwsgi request header
    def test_proxy_003_04(self, env, _class_scope):
        _class_scope._make_response = _UWSGIFaker.hello
        r = env.curl_get(env.mkurl("http", "test1", "/"))
        assert r.response["status"] == 200
        assert r.response["body"] == b"Hello"

        data = _class_scope._request

        assert data[0] == 0x00  # standard WSGI request
        datasize = data[1] + (data[2] * 256)  # read from 16bit little-endian
        assert data[3] == 0x00  # standard WSGI request
        assert len(data) == 4 + datasize

    # empty backend response header values are valid
    def test_proxy_003_05(self, env, _class_scope):
        _class_scope._make_response = _UWSGIFaker.empty_header
        r = env.curl_get(env.mkurl("http", "test1", "/"))
        assert r.response["status"] == 200
        assert "x-empty" in r.response["header"]
        assert r.response["body"] == b"Hello"

