"""
Minimal fake FastCGI responder for testing mod_proxy_fcgi.

Answers every request with a JSON object of the FCGI_PARAMS whose
names start with "TEST_", so tests can check what mod_proxy_fcgi sent.
"""
import json
import socket
import struct
import threading

FCGI_HEADER = ">BBHHBB"
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6


def _recv(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def _parse_params(data):
    params = {}
    pos = 0

    def length():
        nonlocal pos
        if data[pos] & 0x80:
            n = struct.unpack_from(">I", data, pos)[0] & 0x7fffffff
            pos += 4
        else:
            n = data[pos]
            pos += 1
        return n

    while pos < len(data):
        klen = length()
        vlen = length()
        key = data[pos:pos + klen].decode("latin-1")
        pos += klen
        params[key] = data[pos:pos + vlen].decode("latin-1")
        pos += vlen
    return params


def _record(rtype, rid, content=b""):
    return struct.pack(FCGI_HEADER, 1, rtype, rid, len(content), 0, 0) + content


def _handle(conn):
    try:
        params = b""
        while True:
            _, rtype, rid, clen, plen, _ = struct.unpack(FCGI_HEADER,
                                                         _recv(conn, 8))
            content = _recv(conn, clen)
            _recv(conn, plen)
            if rtype == FCGI_PARAMS:
                params += content
            elif rtype == FCGI_STDIN and clen == 0:
                break
        body = json.dumps({k: v for k, v in _parse_params(params).items()
                           if k.startswith("TEST_")}).encode()
        out = b"Content-Type: application/json\r\n\r\n" + body
        conn.sendall(_record(FCGI_STDOUT, rid, out)
                     + _record(FCGI_STDOUT, rid)
                     + _record(FCGI_END_REQUEST, rid, b"\0" * 8))
    except (EOFError, OSError):
        pass
    finally:
        conn.close()


class FcgiFaker:
    """Fake FastCGI backend running in a daemon thread."""

    def __init__(self, port: int):
        self._port = port
        self._done = False
        self._sock = None
        self._thread = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self._port))
        self._sock.listen(16)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._done = True
        self._thread.join(timeout=5)
        self._sock.close()

    def _serve(self):
        while not self._done:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(None)
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()
