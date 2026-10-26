import re
import socket
from typing import List, Tuple

import pytest

from .env import H1Conf

# RFC 9110 section 2.5: a request with a higher minor version of a major
# version the server implements is processed as the highest minor version
# of that major version, here HTTP/1.1.


class TestMinorVersion:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H1Conf(env, extras={
            "base": [
                "<Location /echo>",
                "    SetHandler h1test-echo",
                "</Location>",
            ]
        }).install()
        assert env.apache_restart() == 0

    @staticmethod
    def read_responses(sock, count: int) -> List[Tuple[int, bytes]]:
        """Read `count` responses with a Content-Length or chunked body.
        Raises socket.timeout if the server stalls."""
        buf = b""
        result = []
        while len(result) < count:
            m = re.match(rb'HTTP/1\.1 (\d+) [^\r\n]*\r\n(.*?)\r\n\r\n', buf, re.S)
            while not m:
                data = sock.recv(65536)
                assert data, f"connection closed, got {buf!r}"
                buf += data
                m = re.match(rb'HTTP/1\.1 (\d+) [^\r\n]*\r\n(.*?)\r\n\r\n', buf, re.S)
            status, headers, rest = int(m.group(1)), m.group(2), buf[m.end():]
            clen = re.search(rb'(?im)^content-length:\s*(\d+)', headers)
            body = b""
            if clen:
                n = int(clen.group(1))
                while len(rest) < n:
                    rest += sock.recv(65536)
                body, rest = rest[:n], rest[n:]
            elif re.search(rb'(?im)^transfer-encoding:\s*chunked', headers):
                while True:
                    while b"\r\n" not in rest:
                        rest += sock.recv(65536)
                    line, rest = rest.split(b"\r\n", 1)
                    n = int(line, 16)
                    while len(rest) < n + 2:
                        rest += sock.recv(65536)
                    body, rest = body + rest[:n], rest[n + 2:]
                    if n == 0:
                        break
            result.append((status, body))
            buf = rest
        return result

    def exchange(self, env, request: str, count: int = 1):
        with socket.create_connection(('localhost', int(env.http_port))) as sock:
            # no shutdown(SHUT_WR): the server has to find the end of the
            # request by itself, not from the client closing
            sock.settimeout(5)
            sock.sendall(request.encode())
            try:
                return self.read_responses(sock, count)
            except socket.timeout:
                pytest.fail(f"server stalled on: {request!r}")

    # a request without a body is answered, for supported minor versions
    @pytest.mark.parametrize("version", ["1.0", "1.1", "1.2", "1.3", "1.9"])
    @pytest.mark.parametrize("extra", [
        ["GET", ""],
        ["GET", "Content-Length: 0\r\n"],
        ["POST", "Content-Length: 0\r\n"],
    ])
    def test_h1_008_01(self, env, version, extra):
        method, headers = extra
        r = self.exchange(env, f"{method} / HTTP/{version}\r\nHost: localhost\r\n"
                               f"Connection: close\r\n{headers}\r\n")
        assert r[0][0] == 200

    # a request body with Content-Length is read and delimited
    @pytest.mark.parametrize("version", ["1.0", "1.1", "1.2", "1.9"])
    def test_h1_008_02(self, env, version):
        r = self.exchange(env, f"POST /echo HTTP/{version}\r\nHost: localhost\r\n"
                               f"Connection: close\r\nContent-Length: 5\r\n\r\nhello")
        assert r[0] == (200, b"hello")

    # a chunked request body is decoded
    @pytest.mark.parametrize("version", ["1.1", "1.2", "1.9"])
    def test_h1_008_03(self, env, version):
        r = self.exchange(env, f"POST /echo HTTP/{version}\r\nHost: localhost\r\n"
                               f"Connection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
                               f"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
        assert r[0] == (200, b"hello world")

    # the request body ends where its framing says, the next request on the
    # connection is parsed from there
    @pytest.mark.parametrize("version", ["1.1", "1.2", "1.9"])
    def test_h1_008_04(self, env, version):
        r = self.exchange(env,
                          f"POST /echo HTTP/{version}\r\nHost: localhost\r\n"
                          f"Content-Length: 5\r\n\r\nhello"
                          f"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", count=2)
        assert r[0] == (200, b"hello")
        assert r[1][0] == 200

    # a malformed version stays a client error
    @pytest.mark.parametrize("version", ["HTTP/1.x", "HTTP/1", "HTTP/1.11",
                                         "HTTP/x.1", "http/1.2"])
    def test_h1_008_05(self, env, version):
        r = self.exchange(env, f"GET / {version}\r\nHost: localhost\r\n"
                               f"Connection: close\r\n\r\n")
        assert r[0][0] == 400

    # Other major versions are not covered by the rule for minor versions. The
    # server answers once the client has finished sending, as before.
    @pytest.mark.parametrize("version", ["2.0", "9.9"])
    def test_h1_008_06(self, env, version):
        with socket.create_connection(('localhost', int(env.http_port))) as sock:
            sock.settimeout(5)
            sock.sendall(f"GET / HTTP/{version}\r\nHost: localhost\r\n\r\n".encode())
            sock.shutdown(socket.SHUT_WR)
            r = self.read_responses(sock, 1)
        assert r[0][0] == 200
