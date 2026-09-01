import socket
from threading import Thread

import pytest

from pyhttpd.conf import HttpdConf
from .env import TCPFaker


class _StatusLineBackend(TCPFaker):
    """Backend that sends various status line formats."""

    def __init__(self, host, port, mode="final-status-sep-cr"):
        super().__init__(host, port)
        self._mode = mode

    def _make_response(self, data):
        if self._mode == "final-status-sep-cr":
            return (
                b"HTTP/1.1 200\rX-Foobar: abc\r\n"
                b"Content-Length: 2\r\n"
                b"Content-Type: text/plain\r\n"
                b"\r\n"
                b"OK"
            )
        elif self._mode == "interim-status-cr":
            return (
                b"HTTP/1.1 103 Early\rX-Foobar: abc\r\n"
                b"X-Early: whatever\r\n"
                b"\r\n"
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 2\r\n"
                b"Content-Type: text/plain\r\n"
                b"\r\n"
                b"OK"
            )
        elif self._mode == "interim-102":
            return (
                b"HTTP/1.1 102 Processing\r\n"
                b"\r\n"
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 2\r\n"
                b"Content-Type: text/plain\r\n"
                b"\r\n"
                b"OK"
            )
        return super()._make_response(data)


def _recv_all(sock, timeout=5):
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data


class TestStatusLineCR:
    """Verify that bare CR in backend status lines is rejected.

    Two cases:
    1. Final response with CR at the separator position (byte 3 of status_line)
    2. Interim 1xx response with CR in the reason phrase
    """

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port,
                         doc_root="htdocs", with_ssl=False)
        conf.add([
            f"ProxyPass / http://127.0.0.1:{env.http_port2}/",
            f"ProxyPassReverse / http://127.0.0.1:{env.http_port2}/",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield

    def test_proxy_06_001_final_status_sep_cr(self, env):
        """A final response with CR at status-code separator must not
        forward attacker text as the reason phrase."""
        faker = _StatusLineBackend("127.0.0.1", env.http_port2,
                                 mode="final-status-sep-cr")
        faker.start()
        try:
            with socket.create_connection(('localhost', int(env.http_port))) as sock:
                req = (
                    f"GET / HTTP/1.0\r\n"
                    f"Host: test1.{env.http_tld}\r\n"
                    f"\r\n"
                )
                sock.sendall(req.encode())
                sock.shutdown(socket.SHUT_WR)
                raw = _recv_all(sock)
        finally:
            faker.stop()

        status_line = raw.split(b"\r\n")[0]
        assert b"\r" not in status_line[:-1] if status_line.endswith(b"\r") else b"\r" not in status_line, \
            f"bare CR in status line: {status_line!r}"
        assert b"X-Foobar" not in status_line, \
            f"attacker text in status line: {status_line!r}"
        assert b"X-Foobar" not in raw.split(b"\r\n\r\n")[0], \
            f"injected header in response headers: {raw.split(b'\\r\\n\\r\\n')[0]!r}"

        env.httpd_error_log.ignore_recent(
            lognos=["AH00957", "AH01106", "AH01114"]
        )

    def test_proxy_06_002_interim_status_cr(self, env):
        """An interim 103 response with CR in the reason phrase must not
        forward the bare CR to the client."""
        faker = _StatusLineBackend("127.0.0.1", env.http_port2,
                                 mode="interim-status-cr")
        faker.start()
        try:
            with socket.create_connection(('localhost', int(env.http_port))) as sock:
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: test1.{env.http_tld}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
                sock.sendall(req.encode())
                sock.shutdown(socket.SHUT_WR)
                raw = _recv_all(sock)
        finally:
            faker.stop()

        # Split into individual response blocks. The 103 interim response
        # comes before the final 200.  Check every status line for bare CR.
        lines = raw.split(b"\r\n")
        for line in lines:
            if line.startswith(b"HTTP/"):
                assert b"\r" not in line, \
                    f"bare CR in status line: {line!r}"
                assert b"X-Foobar" not in line, \
                    f"attacker text in status line: {line!r}"

        headers_section = raw.split(b"\r\n\r\n")[0]
        assert b"X-Foobar" not in headers_section, \
            f"injected header in response: {headers_section!r}"

        env.httpd_error_log.ignore_recent(
            lognos=["AH01106"]
        )

    def test_proxy_06_003_interim_102_ok(self, env):
        """A well-formed 102 Processing interim response is forwarded
        correctly, followed by the final 200."""
        faker = _StatusLineBackend("127.0.0.1", env.http_port2,
                                   mode="interim-102")
        faker.start()
        try:
            with socket.create_connection(('localhost', int(env.http_port))) as sock:
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: test1.{env.http_tld}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
                sock.sendall(req.encode())
                sock.shutdown(socket.SHUT_WR)
                raw = _recv_all(sock)
        finally:
            faker.stop()

        status_lines = [l for l in raw.split(b"\r\n")
                        if l.startswith(b"HTTP/")]
        assert len(status_lines) == 2, \
            f"expected 2 status lines (102 + 200), got {len(status_lines)}: {status_lines!r}"
        assert b"102" in status_lines[0], \
            f"first status line should be 102: {status_lines[0]!r}"
        assert b"200" in status_lines[1], \
            f"second status line should be 200: {status_lines[1]!r}"
