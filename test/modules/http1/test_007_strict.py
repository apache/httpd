import re
import socket
from typing import List, Optional

import pytest

from .env import H1Conf


class TestRequestStrict:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H1Conf(env)
        conf.add([
            "HttpProtocolOptions Strict",
        ])
        conf.install()
        assert env.apache_restart() == 0

    # strict tests from t/apache/http_strict.t
    # possible expected results:
    #   0:       any HTTP error
    #   1:       any HTTP success
    #   200-500: specific HTTP status code
    #   undef:   HTTPD should drop connection without error message
    @pytest.mark.parametrize(["intext", "status"], [
        ["GET / HTTP/1.0\n\n", 400],
        ["G/T / HTTP/1.0\r\n\r\n", 400],
        ["GET / HTTP/1.0  \r\nHost: localhost\r\n\r\n", 400],
        ["GET / HTTP/1.0\r\nFoo: b\x01ar\r\n\r\n", 400],
        ["GET / HTTP/1.0\r\nF\x01o: bar\r\n\r\n", 400],
        ["GET / HTTP/1.0\r\r", None],
        ["GET / HTTP/1.0\r\nHost: localhost\r\nHost: localhost\r\n\r\n", 400],
        ["GET http://017700000001/ HTTP/1.0\r\n\r\n", 400],
        ["GET http://0x7f.1/ HTTP/1.0\r\n\r\n", 400],
        ["GET http://127.01.0.1/ HTTP/1.0\r\n\r\n", 400],
        ["GET http://%3127.0.0.1/ HTTP/1.0\r\n\r\n", 400],
        ["GET / HTTP/1.0\r\nHost: localhost:80\r\nHost: localhost:80\r\n\r\n", 400],
        ["GET http://foo@localhost:80/ HTTP/1.0\r\n\r\n", 400],
        ["GET / HTTP/1.0\r\nHost: 4714::abcd:8001\r\n\r\n", 400],
        ["GET / HTTP/1.0\r\nHost: abc\xa0\r\n\r\n", 400],
        ["GET / HTTP/1.0\r\nHost: foo_bar.example.com\r\n\r\n", 200],
        ["GET http://foo_bar/ HTTP/1.0\r\n\r\n", 200],
    ])
    def test_h1_007_01(self, env, intext, status: Optional[int]):
        with socket.create_connection(('localhost', int(env.http_port))) as sock:
            # on some OS, the server does not see our connection until there is
            # something incoming
            sock.sendall(intext.encode())
            sock.shutdown(socket.SHUT_WR)
            buff = sock.recv(1024)
            msg = buff.decode()
            if status is None:
                assert len(msg) == 0, f"unexpected answer: {msg}"
            else:
                assert len(msg) > 0, "no answer from server"
                rlines = msg.splitlines()
                response = rlines[0]
                m = re.match(r'^HTTP/1.1 (\d+)\s+(\S+)', response)
                assert m, f"unrecognized response: {rlines}"
                if status == 1:
                    assert int(m.group(1)) >= 200
                elif status == 90:
                    assert len(rlines) >= 1, f"{rlines}"
                elif status > 0:
                    assert int(m.group(1)) == status, f"{rlines}"
                else:
                    assert int(m.group(1)) >= 400, f"{rlines}"

    @pytest.mark.parametrize(["hvalue", "expvalue", "status", "lognos"], [
        ['"123"', '123', 200, None],
        ['"123 "', '123 ', 200, None],       # trailing space stays
        ['"123\t"', '123\t', 200, None],     # trailing tab stays
        ['" 123"', '123', 200, None],        # leading space is stripped
        ['"          123"', '123', 200, None],  # leading spaces are stripped
        ['"\t123"', '123', 200, None],       # leading tab is stripped
        ['"expr=%{unescape:123%0A 123}"', '', 500, ["AH02430"]],  # illegal char
        ['" \t "', '', 200, None],           # just ws
    ])
    def test_h1_007_02(self, env, hvalue, expvalue, status, lognos: Optional[List[str]]):
        hname = 'ap-test-007'
        conf = H1Conf(env, extras={
            f'test1.{env.http_tld}': [
                '<Location /index.html>',
                f'Header add {hname} {hvalue}',
                '</Location>',
            ]
        })
        conf.add_vhost_test1(proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_get(url, options=['--http1.1'])
        assert r.response["status"] == status
        if int(status) < 400:
            assert r.response["header"][hname] == expvalue
        #
        if lognos is not None:
            env.httpd_error_log.ignore_recent(lognos = lognos)

    @pytest.mark.parametrize(["hvalue", "expvalue"], [
        ['123', '123'],
        ['123 ', '123'],    # trailing space is stripped
        ['123\t', '123'],    # trailing tab is stripped
        [' 123', '123'],    # leading space is stripped
        ['          123', '123'],  # leading spaces are stripped
        ['\t123', '123'],  # leading tab is stripped
    ])
    def test_h1_007_03(self, env, hvalue, expvalue):
        # same as 007_02, but http1 proxied
        hname = 'ap-test-007'
        conf = H1Conf(env, extras={
            f'test1.{env.http_tld}': [
                '<Location /index.html>',
                f'Header add {hname} "{hvalue}"',
                '</Location>',
            ]
        })
        conf.add_vhost_test1(proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "test1", "/proxy/index.html")
        r = env.curl_get(url, options=['--http1.1'])
        assert r.response["status"] == 200
        assert r.response["header"][hname] == expvalue
