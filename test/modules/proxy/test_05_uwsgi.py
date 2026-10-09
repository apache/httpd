import pytest

from pyhttpd.conf import HttpdConf
from .env import TCPFaker


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


class TestProxyUwsgi:

    @pytest.fixture(autouse=True, scope='class')
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

    # verify uwsgi request header
    def test_proxy_005_01(self, env, _class_scope):
        _class_scope._make_response = _UWSGIFaker.hello
        r = env.curl_get(env.mkurl("http", "test1", "/"))
        assert r.response["status"] == 200
        assert r.response["body"] == b"Hello"

        data = _class_scope._request

        assert data[0] == 0x00  # standard WSGI request
        datasize = data[1] + (data[2] * 256)  # read from 16bit little-endian
        assert data[3] == 0x00  # standard WSGI request
        assert len(data) == 4 + datasize

