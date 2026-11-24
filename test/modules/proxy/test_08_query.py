import time

import pytest

from pyhttpd.conf import HttpdConf
from .env import TCPFaker


class _HttpFaker(TCPFaker):

    def _make_response(self, data):
        return (b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/csv\r\n"
                b"Content-Length: 6\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"a,b,c\n")


def _ajp_packet(body):
    return b"\x41\x42" + len(body).to_bytes(2, "big") + body


class _AjpFaker(TCPFaker):

    def _make_response(self, data):
        # SEND_HEADERS 200 "OK" without headers, then END_RESPONSE
        headers = (b"\x04" + b"\x00\xc8"
                   + len(b"OK").to_bytes(2, "big") + b"OK" + b"\x00"
                   + b"\x00\x00")
        return _ajp_packet(headers) + _ajp_packet(b"\x05\x00")


def _wait_request(faker, timeout=5):
    end = time.time() + timeout
    while faker._request is None and time.time() < end:
        time.sleep(0.05)
    return faker._request


def _query(env, url, body, ctype="application/sql"):
    return env.curl_raw([url], options=[
        "-X", "QUERY", "--data-binary", body, "-H", f"Content-Type: {ctype}",
    ])


class TestProxyQueryHttp:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        faker = _HttpFaker("127.0.0.1", env.http_port2)
        faker.start()
        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port)
        conf.add([f"ProxyPass / http://127.0.0.1:{env.http_port2}/"])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield faker
        faker.stop()

    # mod_proxy_http forwards method, Content-Type and content
    def test_proxy_008_01(self, env, _class_scope):
        _class_scope._request = None
        body = "SELECT * FROM rfc WHERE year > 2020"
        r = _query(env, env.mkurl("http", "test1", "/rfc-index?x=1"), body)
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        assert r.response["body"] == b"a,b,c\n"
        req = _wait_request(_class_scope)
        assert req is not None
        head, _, content = req.partition(b"\r\n\r\n")
        assert head.startswith(b"QUERY /rfc-index?x=1 HTTP/1.1\r\n"), req
        assert b"\r\nContent-Type: application/sql" in head, req
        assert content == body.encode(), req


class TestProxyQueryAjp:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.require(env.has_shared_module("proxy_ajp"), "mod_proxy_ajp not available",
                    dep="mod_proxy_ajp",
                    detected=f"no mod_proxy_ajp.so in {env.libexec_dir}")
        faker = _AjpFaker("127.0.0.1", env.http_port2)
        faker.start()
        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port)
        conf.add([f"ProxyPass / ajp://127.0.0.1:{env.http_port2}/"])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield faker
        faker.stop()

    # AJP13 has no code for QUERY: it is sent as a stored method attribute
    def test_proxy_008_02(self, env, _class_scope):
        _class_scope._request = None
        r = _query(env, env.mkurl("http", "test1", "/"), "q=1")
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        req = _wait_request(_class_scope)
        assert req is not None
        # 0x12 0x34 magic, length, FORWARD_REQUEST (2), method
        assert req[0:2] == b"\x12\x34", req
        assert req[4] == 0x02, req
        assert req[5] == 0xff, req
        # SC_A_STORED_METHOD (13) followed by the AJP string "QUERY"
        assert b"\x0d\x00\x05QUERY\x00" in req, req
