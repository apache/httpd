"""
Minimal fake FastCGI responder backend for testing mod_proxy_fcgi.

Listens on a TCP port and speaks the FastCGI wire protocol (records only,
no multiplexing). It reads and discards FCGI_BEGIN_REQUEST, FCGI_PARAMS
and FCGI_STDIN, then writes back an intentionally malformed FCGI_STDOUT
stream: a normal chunk of body data, followed by a zero-length FCGI_STDOUT
record (which per the FastCGI spec marks the end of the stream), followed
by *more* FCGI_STDOUT data. Some backends (PHP-FPM hitting PHP bug #72185,
for one) really do this, and the extra data after the stream-ending empty
record must be discarded rather than forwarded down the output filter
chain (see PR66168).
"""
import socket
import struct
import threading


FCGI_BEGIN_REQUEST = 1
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6

HEADER_LEN = 8

BODY_BEFORE_EOS = b"before-eos-" * 200
BODY_AFTER_EOS = b"after-eos-" * 200


def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _recv_record_header(conn):
    header = _recv_exact(conn, HEADER_LEN)
    if header is None:
        return None
    _version, rtype, req_id, content_len, pad_len = struct.unpack(
        ">BBHHB", header[:7])
    return rtype, req_id, content_len, pad_len


def _recv_record(conn):
    """Read one complete FastCGI record, returning (type, req_id, content)."""
    hdr = _recv_record_header(conn)
    if hdr is None:
        return None
    rtype, req_id, content_len, pad_len = hdr
    content = _recv_exact(conn, content_len) if content_len else b""
    if content is None:
        return None
    if pad_len:
        if _recv_exact(conn, pad_len) is None:
            return None
    return rtype, req_id, content


def _send_record(conn, rtype, req_id, content=b""):
    header = struct.pack(">BBHHBB", 1, rtype, req_id, len(content), 0, 0)
    conn.sendall(header + content)


def _handle(conn):
    try:
        begin = _recv_record(conn)
        if begin is None or begin[0] != FCGI_BEGIN_REQUEST:
            return
        req_id = begin[1]

        # Drain FCGI_PARAMS until the stream-ending empty record.
        while True:
            rec = _recv_record(conn)
            if rec is None:
                return
            if rec[0] == FCGI_PARAMS and len(rec[2]) == 0:
                break

        # Drain FCGI_STDIN until the stream-ending empty record.
        while True:
            rec = _recv_record(conn)
            if rec is None:
                return
            if rec[0] == FCGI_STDIN and len(rec[2]) == 0:
                break

        headers = b"Content-Type: text/plain\r\n\r\n"
        _send_record(conn, FCGI_STDOUT, req_id, headers + BODY_BEFORE_EOS)

        # Premature stream-ending empty record (the PHP-FPM / PHP bug
        # #72185 pattern), immediately followed by more STDOUT data that
        # must never reach an output filter chain that already saw EOS.
        _send_record(conn, FCGI_STDOUT, req_id, b"")
        _send_record(conn, FCGI_STDOUT, req_id, BODY_AFTER_EOS)

        _send_record(conn, FCGI_STDOUT, req_id, b"")
        _send_record(conn, FCGI_END_REQUEST, req_id,
                      struct.pack(">LBxxx", 0, 0))
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
