"""Raw socket helper for protocol-level tests.

Port of the raw-socket side of Apache::TestRequest (``vhost_socket`` / ``getline``
/ ``socket_trace``). Many httpd tests bypass the HTTP client and speak HTTP (or a
malformed approximation of it) directly over a TCP socket -- e.g. CVE regression
tests that send a hand-built request line and assert on the raw status line.

:class:`VhostSocket` wraps a ``socket.socket`` with the small line-oriented API
those tests use: ``print`` (send), ``getline`` (read one CRLF/LF-terminated line),
``read`` (drain), and ``connected``. It is a context manager so callers can use
``with http.vhost_socket(...) as sock:``.
"""

from __future__ import annotations

import socket
import ssl as _ssl


class VhostSocket:
    """A thin line-oriented wrapper over a connected TCP (optionally TLS) socket."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buf = b""
        self._trace = False

    # -- Apache::TestRequest socket API ----------------------------------

    @property
    def connected(self) -> bool:
        try:
            self._sock.getpeername()
            return True
        except OSError:
            return False

    def socket_trace(self, on: bool = True) -> None:
        """Enable echoing of sent/received data (Apache::TestRequest::socket_trace)."""
        self._trace = on

    def print(self, data: str | bytes) -> int:
        """Send ``data`` (str encoded latin-1, preserving raw bytes). Returns 1 (ok)."""
        raw = data.encode("latin-1") if isinstance(data, str) else data
        if self._trace:
            print(f"S> {raw!r}")
        self._sock.sendall(raw)
        return 1

    # Perl idiom: $sock->print(...). Keep `send` too for clarity.
    send = print

    def getline(self, timeout: float | None = 10.0) -> str | None:
        """Read one line (up to and incl. the newline), returned as a str.

        Mirrors Apache::TestRequest::getline: returns the line including its
        trailing ``\\n``, or None at EOF. Buffers across reads.
        """
        if timeout is not None:
            self._sock.settimeout(timeout)
        while b"\n" not in self._buf:
            try:
                chunk = self._sock.recv(4096)
            except (TimeoutError, socket.timeout):
                break
            if not chunk:
                break
            self._buf += chunk
        if not self._buf:
            return None
        nl = self._buf.find(b"\n")
        if nl == -1:
            line, self._buf = self._buf, b""
        else:
            line, self._buf = self._buf[: nl + 1], self._buf[nl + 1 :]
        text = line.decode("latin-1")
        if self._trace:
            print(f"C< {text!r}")
        return text

    def read(self, timeout: float | None = 10.0) -> str:
        """Drain and return everything still readable (decoded latin-1)."""
        if timeout is not None:
            self._sock.settimeout(timeout)
        data = self._buf
        self._buf = b""
        while True:
            try:
                chunk = self._sock.recv(4096)
            except (TimeoutError, socket.timeout):
                break
            if not chunk:
                break
            data += chunk
        return data.decode("latin-1")

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self) -> VhostSocket:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def open_vhost_socket(
    host: str, port: int, *, use_ssl: bool = False, timeout: float = 10.0
) -> VhostSocket:
    """Open a raw TCP (optionally TLS) connection to ``host:port``.

    TLS connections are wrapped without certificate verification -- protocol
    tests care about the wire behaviour, not the peer identity (matching the
    Perl tests, which use IO::Socket::SSL with the test CA / no verification).
    """
    raw = socket.create_connection((host, port), timeout=timeout)
    if use_ssl:
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        raw = ctx.wrap_socket(raw, server_hostname=host)
    return VhostSocket(raw)
