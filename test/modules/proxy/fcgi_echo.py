"""
Minimal FastCGI responder for testing mod_proxy_fcgi.

Answers every request with a JSON body holding the CGI variables it was
sent, so that a test can check what mod_proxy_fcgi passed to the backend.
"""
import json
import socket
import struct
import threading

FCGI_BEGIN_REQUEST = 1
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6


def _read_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def _read_record(conn):
    version, rtype, req_id, clen, plen, _ = \
        struct.unpack("!BBHHBB", _read_exact(conn, 8))
    content = _read_exact(conn, clen)
    _read_exact(conn, plen)
    return rtype, req_id, content


def _parse_params(data):
    params = {}
    pos = 0

    def length():
        nonlocal pos
        if data[pos] & 0x80:
            n = struct.unpack_from("!I", data, pos)[0] & 0x7fffffff
            pos += 4
        else:
            n = data[pos]
            pos += 1
        return n

    while pos < len(data):
        nlen = length()
        vlen = length()
        name = data[pos:pos + nlen].decode("latin-1")
        pos += nlen
        params[name] = data[pos:pos + vlen].decode("latin-1")
        pos += vlen
    return params


def _record(rtype, req_id, content=b""):
    return struct.pack("!BBHHBB", 1, rtype, req_id, len(content), 0, 0) + content


class FcgiEcho:

    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._socket = None
        self._thread = None
        self._done = False

    def start(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self._host, self._port))
        self._socket.listen(5)
        self._socket.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._done = True
        self._thread.join(timeout=5)
        self._socket.close()

    def _serve(self):
        while not self._done:
            try:
                conn, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(5)
                try:
                    self._handle(conn)
                except (ConnectionError, socket.timeout, struct.error):
                    pass

    def _handle(self, conn):
        req_id = 1
        params = b""
        while True:
            rtype, req_id, content = _read_record(conn)
            if rtype == FCGI_PARAMS:
                params += content
            elif rtype == FCGI_STDIN and not content:
                break
        body = json.dumps(_parse_params(params)).encode()
        head = b"Content-Type: application/json\r\n\r\n"
        conn.sendall(_record(FCGI_STDOUT, req_id, head + body)
                     + _record(FCGI_STDOUT, req_id)
                     + _record(FCGI_END_REQUEST, req_id, b"\0" * 8))
