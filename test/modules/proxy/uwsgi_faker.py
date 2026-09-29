"""
Minimal fake uWSGI backend for testing mod_proxy_uwsgi.

Listens on a TCP port and speaks the uWSGI wire protocol.  mod_proxy_uwsgi
sends a binary uwsgi packet (4-byte header + CGI key/value pairs) followed by
the optional request body, and expects a plain HTTP/1.x response back.

The QUERY_STRING CGI variable controls what the response looks like:

  QUERY_STRING=""     - normal 200 response, no Transfer-Encoding
  QUERY_STRING="te=1" - 200 response with Transfer-Encoding: chunked injected
                        (simulates a buggy Python app; mod_proxy_uwsgi must
                        strip it before forwarding to the client)
"""
import socket
import struct
import threading


BODY = b'{"host": "uwsgi-faker"}'


def _parse_uwsgi_vars(data):
    """Parse the CGI key/value payload from a uwsgi packet.

    Packet layout (from the uWSGI protocol spec):
      [modifier1: u8][payload_len: u16le][modifier2: u8][payload: bytes]
    Payload is a sequence of:
      [keylen: u16le][key: bytes][vallen: u16le][val: bytes]

    Returns a dict of the decoded variables, or {} on parse error.
    """
    if len(data) < 4:
        return {}
    payload_len = struct.unpack_from("<H", data, 1)[0]
    if len(data) < 4 + payload_len:
        return {}
    pos = 4
    end = 4 + payload_len
    vars_ = {}
    while pos < end:
        if pos + 2 > end:
            break
        klen = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if pos + klen > end:
            break
        key = data[pos:pos + klen].decode("latin-1")
        pos += klen
        if pos + 2 > end:
            break
        vlen = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if pos + vlen > end:
            break
        val = data[pos:pos + vlen].decode("latin-1")
        pos += vlen
        vars_[key] = val
    return vars_


def _recv_uwsgi_request(conn):
    """Read a complete uwsgi request packet from the connection.

    Returns the raw bytes of the complete packet (header + payload), or b""
    on connection close.
    """
    # Read the 4-byte uwsgi header
    header = b""
    while len(header) < 4:
        chunk = conn.recv(4 - len(header))
        if not chunk:
            return b""
        header += chunk

    payload_len = struct.unpack_from("<H", header, 1)[0]

    payload = b""
    while len(payload) < payload_len:
        chunk = conn.recv(payload_len - len(payload))
        if not chunk:
            return b""
        payload += chunk

    return header + payload


def _handle(conn):
    try:
        packet = _recv_uwsgi_request(conn)
        if not packet:
            return

        cgi_vars = _parse_uwsgi_vars(packet)
        qs = cgi_vars.get("QUERY_STRING", "")
        inject_te = "te=1" in qs.split("&")

        headers = [
            b"HTTP/1.1 200 OK",
            b"Server: UwsgiFaker",
            b"Content-Type: application/json",
        ]
        if inject_te:
            # Inject the invalid header that mod_proxy_uwsgi must strip
            headers.append(b"Transfer-Encoding: chunked")
        headers.append(b"Content-Length: " + str(len(BODY)).encode())
        headers.append(b"")
        headers.append(b"")

        conn.sendall(b"\r\n".join(headers) + BODY)
    finally:
        conn.close()


class UwsgiFaker:
    """Fake uWSGI backend running in a daemon thread."""

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
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._done = True
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve(self):
        while not self._done:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            t = threading.Thread(target=_handle, args=(conn,), daemon=True)
            t.start()
"""
Minimal fake uWSGI backend for testing mod_proxy_uwsgi.

Listens on a TCP port and speaks the uWSGI wire protocol.  mod_proxy_uwsgi
sends a binary uwsgi packet (4-byte header + CGI key/value pairs) followed by
the optional request body, and expects a plain HTTP/1.x response back.

The QUERY_STRING CGI variable controls what the response looks like:

  QUERY_STRING=""     - normal 200 response, no Transfer-Encoding
  QUERY_STRING="te=1" - 200 response with Transfer-Encoding: chunked injected
                        (simulates a buggy Python app; mod_proxy_uwsgi must
                        strip it before forwarding to the client)
"""
import socket
import struct
import threading


BODY = b'{"host": "uwsgi-faker"}'


def _parse_uwsgi_vars(data):
    """Parse the CGI key/value payload from a uwsgi packet.

    Packet layout (from the uWSGI protocol spec):
      [modifier1: u8][payload_len: u16le][modifier2: u8][payload: bytes]
    Payload is a sequence of:
      [keylen: u16le][key: bytes][vallen: u16le][val: bytes]

    Returns a dict of the decoded variables, or {} on parse error.
    """
    if len(data) < 4:
        return {}
    payload_len = struct.unpack_from("<H", data, 1)[0]
    if len(data) < 4 + payload_len:
        return {}
    pos = 4
    end = 4 + payload_len
    vars_ = {}
    while pos < end:
        if pos + 2 > end:
            break
        klen = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if pos + klen > end:
            break
        key = data[pos:pos + klen].decode("latin-1")
        pos += klen
        if pos + 2 > end:
            break
        vlen = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if pos + vlen > end:
            break
        val = data[pos:pos + vlen].decode("latin-1")
        pos += vlen
        vars_[key] = val
    return vars_


def _recv_uwsgi_request(conn):
    """Read a complete uwsgi request packet from the connection.

    Returns the raw bytes of the complete packet (header + payload), or b""
    on connection close.
    """
    # Read the 4-byte uwsgi header
    header = b""
    while len(header) < 4:
        chunk = conn.recv(4 - len(header))
        if not chunk:
            return b""
        header += chunk

    payload_len = struct.unpack_from("<H", header, 1)[0]

    payload = b""
    while len(payload) < payload_len:
        chunk = conn.recv(payload_len - len(payload))
        if not chunk:
            return b""
        payload += chunk

    return header + payload


def _handle(conn):
    try:
        packet = _recv_uwsgi_request(conn)
        if not packet:
            return

        cgi_vars = _parse_uwsgi_vars(packet)
        qs = cgi_vars.get("QUERY_STRING", "")
        inject_te = "te=1" in qs.split("&")

        headers = [
            b"HTTP/1.1 200 OK",
            b"Server: UwsgiFaker",
            b"Content-Type: application/json",
        ]
        if inject_te:
            # Inject the invalid header that mod_proxy_uwsgi must strip
            headers.append(b"Transfer-Encoding: chunked")
        headers.append(b"Content-Length: " + str(len(BODY)).encode())
        headers.append(b"")
        headers.append(b"")

        conn.sendall(b"\r\n".join(headers) + BODY)
    finally:
        conn.close()


class UwsgiFaker:
    """Fake uWSGI backend running in a daemon thread."""

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
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._done = True
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve(self):
        while not self._done:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            t = threading.Thread(target=_handle, args=(conn,), daemon=True)
            t.start()
