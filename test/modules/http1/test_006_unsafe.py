import re
import socket
from typing import List, Optional

import pytest

from .env import H1Conf

class TestRequestUnsafe:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H1Conf(env)
        conf.add([
            "HttpProtocolOptions Unsafe",
        ])
        conf.install()
        assert env.apache_restart() == 0

    # unsafe tests from t/apache/http_strict.t
    # possible expected results:
    #   0:       any HTTP error
    #   1:       any HTTP success
    #   200-500: specific HTTP status code
    #   None:   HTTPD should drop connection without error message
    @pytest.mark.parametrize(["intext", "status", "lognos"], [
        ["GET / HTTP/1.0\r\n\r\n", 1, None],
        ["GET / HTTP/1.0\n\n", 1, None],
        ["get / HTTP/1.0\r\n\r\n", 501, ["AH00135"]],
        ["G ET / HTTP/1.0\r\n\r\n", 400, None],
        ["G\0ET / HTTP/1.0\r\n\r\n", 400, None],
        ["G/T / HTTP/1.0\r\n\r\n", 501, ["AH00135"]],
        ["GET /\0 HTTP/1.0\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\0\r\n\r\n", 400, None],
        ["GET\f/ HTTP/1.0\r\n\r\n", 400, None],
        ["GET\r/ HTTP/1.0\r\n\r\n", 400, None],
        ["GET\t/ HTTP/1.0\r\n\r\n", 400, None],
        ["GET / HTT/1.0\r\n\r\n", 0, None],
        ["GET / HTTP/1.0\r\nHost: localhost\r\n\r\n", 1, None],
        ["GET / HTTP/2.0\r\nHost: localhost\r\n\r\n", 1, None],
        ["GET / HTTP/1.2\r\nHost: localhost\r\n\r\n", 1, None],
        ["GET / HTTP/1.11\r\nHost: localhost\r\n\r\n", 400, None],
        ["GET / HTTP/10.0\r\nHost: localhost\r\n\r\n", 400, None],
        ["GET / HTTP/1.0  \r\nHost: localhost\r\n\r\n", 200, None],
        ["GET / HTTP/1.0 x\r\nHost: localhost\r\n\r\n", 400, None],
        ["GET / HTTP/\r\nHost: localhost\r\n\r\n", 0, None],
        ["GET / HTTP/0.9\r\n\r\n", 0, None],
        ["GET / HTTP/0.8\r\n\r\n", 0, None],
        ["GET /\x01 HTTP/1.0\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\r\nFoo: bar\r\n\r\n", 200, None],
        ["GET / HTTP/1.0\r\nFoo:bar\r\n\r\n", 200, None],
        ["GET / HTTP/1.0\r\nFoo: b\0ar\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\r\nFoo: b\x01ar\r\n\r\n", 200, None],
        ["GET / HTTP/1.0\r\nFoo\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\r\nFoo bar\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\r\n: bar\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\r\nX: bar\r\n\r\n", 200, None],
        ["GET / HTTP/1.0\r\nFoo bar:bash\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\r\nFoo :bar\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\r\n Foo:bar\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\r\nF\x01o: bar\r\n\r\n", 200, None],
        ["GET / HTTP/1.0\r\nF\ro: bar\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\r\nF\to: bar\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\r\nFo: b\tar\r\n\r\n", 200, None],
        ["GET / HTTP/1.0\r\nFo: bar\r\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\r\r", None, None],
        ["GET /\r\n", 0, None],
        ["GET /#frag HTTP/1.0\r\n", 400, None],
        ["GET / HTTP/1.0\r\nHost: localhost\r\nHost: localhost\r\n\r\n", 200, None],
        ["GET http://017700000001/ HTTP/1.0\r\n\r\n", 200, None],
        ["GET http://0x7f.1/ HTTP/1.0\r\n\r\n", 200, None],
        ["GET http://127.0.0.1/ HTTP/1.0\r\n\r\n", 200, None],
        ["GET http://127.01.0.1/ HTTP/1.0\r\n\r\n", 200, None],
        ["GET http://%3127.0.0.1/ HTTP/1.0\r\n\r\n", 200, None],
        ["GET / HTTP/1.0\r\nHost: localhost:80\r\nHost: localhost:80\r\n\r\n", 200, None],
        ["GET / HTTP/1.0\r\nHost: localhost:80 x\r\n\r", 400, None],
        ["GET http://localhost:80/ HTTP/1.0\r\n\r\n", 200, None],
        ["GET http://localhost:80x/ HTTP/1.0\r\n\r\n", 400, None],
        ["GET http://localhost:80:80/ HTTP/1.0\r\n\r\n", 400, None],
        ["GET http://localhost::80/ HTTP/1.0\r\n\r\n", 400, None],
        ["GET http://foo@localhost:80/ HTTP/1.0\r\n\r\n", 200, None],
        ["GET http://[::1]/ HTTP/1.0\r\n\r\n", 1, None],
        ["GET http://[::1:2]/ HTTP/1.0\r\n\r\n", 1, None],
        ["GET http://[4712::abcd]/ HTTP/1.0\r\n\r\n", 1, None],
        ["GET http://[4712::abcd:1]/ HTTP/1.0\r\n\r\n", 1, None],
        ["GET http://[4712::abcd::]/ HTTP/1.0\r\n\r\n", 400, None],
        ["GET http://[4712:abcd::,]/ HTTP/1.0\r\n\r\n", 1, None],
        ["GET http://[4712::abcd]:8000/ HTTP/1.0\r\n\r\n", 1, None],
        ["GET http://4713::abcd:8001/ HTTP/1.0\r\n\r\n", 400, None],
        ["GET / HTTP/1.0\r\nHost: [::1]\r\n\r\n", 1, None],
        ["GET / HTTP/1.0\r\nHost: [::1:2]\r\n\r\n", 1, None],
        ["GET / HTTP/1.0\r\nHost: [4711::abcd]\r\n\r\n", 1, None],
        ["GET / HTTP/1.0\r\nHost: [4711::abcd:1]\r\n\r\n", 1, None],
        ["GET / HTTP/1.0\r\nHost: [4711:abcd::]\r\n\r\n", 1, None],
        ["GET / HTTP/1.0\r\nHost: [4711::abcd]:8000\r\n\r\n", 1, None],
        ["GET / HTTP/1.0\r\nHost: 4714::abcd:8001\r\n\r\n", 200, None],
        ["GET / HTTP/1.0\r\nHost: abc\xa0\r\n\r\n", 200, None],
        ["GET / HTTP/1.0\r\nHost: abc\\foo\r\n\r\n", 400, None],
        ["GET http://foo/ HTTP/1.0\r\nHost: bar\r\n\r\n", 200, None],
        ["GET http://foo:81/ HTTP/1.0\r\nHost: bar\r\n\r\n", 200, None],
        ["GET http://[::1]:81/ HTTP/1.0\r\nHost: bar\r\n\r\n", 200, None],
        ["GET http://10.0.0.1:81/ HTTP/1.0\r\nHost: bar\r\n\r\n", 200, None],
        ["GET / HTTP/1.0\r\nHost: foo-bar.example.com\r\n\r\n", 200, None],
        ["GET / HTTP/1.0\r\nHost: foo_bar.example.com\r\n\r\n", 200, None],
        ["GET http://foo_bar/ HTTP/1.0\r\n\r\n", 200, None],
    ])
    def test_h1_006_01(self, env, intext, status: Optional[int], lognos: Optional[List[str]]):
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
                assert m or status == 0, f"unrecognized response: {rlines}"
                if status == 1:
                    assert int(m.group(1)) >= 200
                elif status == 0:
                    # headerless 0.9 response, yuk
                    assert len(rlines) >= 1, f"{rlines}"
                elif status > 0:
                    assert int(m.group(1)) == status, f"{rlines}"
                else:
                    assert int(m.group(1)) >= 400, f"{rlines}"
                #
                if lognos is not None:
                    env.httpd_error_log.ignore_recent(lognos = lognos)
