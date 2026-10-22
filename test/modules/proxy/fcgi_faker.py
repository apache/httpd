"""
Minimal FastCGI Responder for testing mod_proxy_fcgi.

Listens on a TCP port and answers every request with the CGI response which
the test registered for its SCRIPT_NAME.  A connection is kept open for as
many requests as the client sends on it, so that the tests can tell whether
mod_proxy_fcgi reused a connection and whether it left it in a usable state.
"""
import socket
import struct
import threading

FCGI_BEGIN_REQUEST = 1
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6

MAX_CONTENT = 65535


def _read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _parse_params(data):
    params = {}
    pos = 0

    def length():
        nonlocal pos
        if data[pos] >> 7:
            n = struct.unpack_from(">I", data, pos)[0] & 0x7fffffff
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


def _record(rtype, request_id, content=b""):
    return struct.pack(">BBHHBx", 1, rtype, request_id, len(content), 0) + content


class FcgiFaker:

    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._socket = None
        self._thread = None
        self._done = False
        self._lock = threading.Lock()
        self._conn_count = 0
        # path -> exact CGI response (headers and body) sent over FCGI_STDOUT
        self.routes = {}
        # what the backend has seen, in order: one dict per request
        self.requests = []

    def start(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self._host, self._port))
        self._socket.listen(8)
        self._socket.settimeout(0.5)
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def stop(self):
        self._done = True
        self._thread.join(timeout=5)
        self._socket.close()

    def reset(self):
        with self._lock:
            self.requests = []

    def _accept(self):
        while not self._done:
            try:
                conn, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._conn_count += 1
                conn_id = self._conn_count
            threading.Thread(target=self._serve, args=(conn, conn_id),
                             daemon=True).start()

    def _serve(self, conn, conn_id):
        conn.settimeout(30)
        request_id = 0
        params = b""
        stdin = b""
        try:
            while True:
                header = _read_exact(conn, 8)
                if header is None:
                    return
                _, rtype, request_id_, clen, plen = struct.unpack(">BBHHBx", header)
                content = _read_exact(conn, clen) if clen else b""
                if plen:
                    _read_exact(conn, plen)
                if rtype == FCGI_BEGIN_REQUEST:
                    request_id = request_id_
                    params = b""
                    stdin = b""
                elif rtype == FCGI_PARAMS:
                    params += content
                elif rtype == FCGI_STDIN:
                    stdin += content
                    if clen == 0:
                        self._respond(conn, conn_id, request_id,
                                      _parse_params(params), stdin)
        except OSError:
            return
        finally:
            conn.close()

    def _respond(self, conn, conn_id, request_id, params, stdin):
        # SCRIPT_NAME is the path of the request, REQUEST_URI stays the one
        # the client sent when the server redirects internally.
        path = params.get("SCRIPT_NAME", "")
        with self._lock:
            self.requests.append({"conn": conn_id, "uri": path,
                                  "params": params, "stdin": stdin})
        if path in self.routes:
            out = self.routes[path]
            if callable(out):
                out = out(params, stdin)
        else:
            out = b"Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\nno route\n"
        for i in range(0, len(out), MAX_CONTENT):
            conn.sendall(_record(FCGI_STDOUT, request_id, out[i:i + MAX_CONTENT]))
        conn.sendall(_record(FCGI_STDOUT, request_id))
        conn.sendall(_record(FCGI_END_REQUEST, request_id,
                             struct.pack(">IBxxx", 0, 0)))
