import socket

import pytest

from pyhttpd.conf import HttpdConf

# the status as answered by the CGI script, or as written by mod_aptest as a
# final response of its own
SCRIPT = "/status_body.py?status={status}&parts={parts}"
PREBUILT = "/pre?status={status}"

BODY = b"SHOULD-NOT-BE-SENT\n"


class TestStatusNoBody:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            "base": [
                "<Location /pre>",
                "    SetHandler aptest-prebuilt",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0

    @staticmethod
    def _recv_all(sock):
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return data
            data += chunk

    @staticmethod
    def _split_response(data, method="GET"):
        """Cut the first response off a byte stream the way a client does:
        by status code and Content-Length, never by what the server closes.
        Returns the response and what is left after it."""
        head, sep, rest = data.partition(b"\r\n\r\n")
        assert sep, f"no complete response header in {data!r}"
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split(" ")[1])
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
            return status, headers, b"", rest
        if headers.get("transfer-encoding") == "chunked":
            body = b""
            while True:
                size_line, _, rest = rest.partition(b"\r\n")
                size = int(size_line.split(b";")[0], 16)
                if size == 0:
                    # no trailers expected
                    assert rest[:2] == b"\r\n", f"trailer: {rest[:20]!r}"
                    return status, headers, body, rest[2:]
                body += rest[:size]
                assert rest[size:size + 2] == b"\r\n"
                rest = rest[size + 2:]
        assert "content-length" in headers, \
            f"body is not delimited, the client reads until close: {headers}"
        n = int(headers["content-length"])
        assert len(rest) >= n, f"short body: {len(rest)} < {n}"
        return status, headers, rest[:n], rest[n:]

    def exchange(self, env, status, method="GET", parts=1, target=SCRIPT):
        """Send two requests on one connection and parse both responses
        from the bytes the server wrote. The second request is a 200 which
        shows the connection is still correctly framed after the first."""
        host = f"cgi.{env.http_tld}"
        first = target.format(status=status, parts=parts)
        second = target.format(status=200, parts=1)
        req = (f"{method} {first} HTTP/1.1\r\n"
               f"Host: {host}\r\n\r\n"
               f"GET {second} HTTP/1.1\r\n"
               f"Host: {host}\r\nConnection: close\r\n\r\n").encode()
        with socket.create_connection(("127.0.0.1", env.http_port),
                                      timeout=10) as sock:
            sock.sendall(req)
            data = self._recv_all(sock)
        resp1 = self._split_response(data, method)
        resp2 = self._split_response(resp1[3])
        assert resp2[3] == b"", f"unexpected data after 2nd response: {resp2[3]!r}"
        return resp1[:3], resp2[:3]

    # a 205 carries no content, whatever the handler writes
    def test_core_012_01(self, env):
        (status, headers, body), _ = self.exchange(env, 205)
        assert status == 205
        assert body == b""

    # without content the response is delimited by Content-Length: 0
    def test_core_012_02(self, env):
        (status, headers, body), _ = self.exchange(env, 205)
        assert status == 205
        assert headers.get("content-length") == "0"
        assert "transfer-encoding" not in headers

    # the connection stays usable, nothing of the discarded body shows up
    def test_core_012_03(self, env):
        _, (status, headers, body) = self.exchange(env, 205)
        assert status == 200
        assert body == BODY

    # a HEAD request is answered without content and keeps the connection
    def test_core_012_04(self, env):
        (status, headers, body), (status2, _, body2) = \
            self.exchange(env, 205, method="HEAD")
        assert status == 205
        assert body == b""
        assert (status2, body2) == (200, BODY)

    # 204 stays without content and without content related headers
    def test_core_012_05(self, env):
        (status, headers, body), (status2, _, body2) = self.exchange(env, 204)
        assert status == 204
        assert body == b""
        assert "content-length" not in headers
        assert "transfer-encoding" not in headers
        assert (status2, body2) == (200, BODY)

    # 304 stays without content
    def test_core_012_06(self, env):
        (status, headers, body), (status2, _, body2) = self.exchange(env, 304)
        assert status == 304
        assert body == b""
        assert (status2, body2) == (200, BODY)

    # other 2xx statuses still carry the body
    @pytest.mark.parametrize("code", [200, 201, 202])
    def test_core_012_07(self, env, code):
        (status, headers, body), _ = self.exchange(env, code)
        assert status == code
        assert body == BODY

    # the same when the handler writes its content in several flushed parts
    def test_core_012_08(self, env):
        (status, headers, body), (status2, _, body2) = \
            self.exchange(env, 205, parts=3)
        assert status == 205
        assert body == b""
        assert headers.get("content-length") == "0"
        assert (status2, body2) == (200, BODY)

    # the same when the response is a final response bucket written by the
    # handler itself, 204 and 304 included
    @pytest.mark.parametrize("code", [204, 205, 304])
    def test_core_012_09(self, env, code):
        (status, headers, body), (status2, _, body2) = \
            self.exchange(env, code, target=PREBUILT)
        assert status == code
        assert body == b""
        if code == 205:
            assert headers.get("content-length") == "0"
            assert "transfer-encoding" not in headers
        assert (status2, body2) == (200, BODY)
