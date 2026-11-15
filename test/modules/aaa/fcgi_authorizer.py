"""Minimal FastCGI AUTHORIZER-role responder, used to reproduce and verify
the fix for BZ 65984: handle_response() in mod_authnz_fcgi.c only collected
a non-200 response body into rspbuf the one time it first saw the end of
the headers, silently dropping any body data that arrived in a later
FCGI_STDOUT record (e.g. because the authenticator flushed its output
stream between the headers and the body, or between body chunks). It does
not implement or depend on any FastCGI client library -- just the handful
of record types mod_authnz_fcgi's handle_response() actually sends and
expects, per the FastCGI spec.

The response shape is chosen per-request from the client's
"X-Test-Case" request header (forwarded to the backend as the
HTTP_X_TEST_CASE FastCGI param by ap_add_cgi_vars()), so one running
backend can serve every scenario the regression test needs:

  one-record           headers and body in the same FCGI_STDOUT record
  split-headers-body   headers and body in separate records (the
                        original BZ 65984 reproduction)
  multi-chunk-body     body split across several records after the
                        headers are already complete
  split-headers        the header block itself split across records,
                        including mid-terminator
  ignored-200          a 200 response with a body that must be ignored

"X-Test-Status" (default 401) and "X-Test-Bodylen" (default: a short fixed
marker) select the status line and the exact body length, to probe the
NON200_RESPONSE_BUF_LEN (8192-byte) rspbuf boundary.
"""
import socket
import struct
import threading

FCGI_VERSION_1 = 1
FCGI_BEGIN_REQUEST = 1
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDOUT = 6
FCGI_REQUEST_COMPLETE = 0

BODY_MARKER = b"denied by fcgi_authorizer.py\n"


def _header(rec_type, request_id, content_len, padding_len=0):
    return struct.pack(
        "!BBHHBB", FCGI_VERSION_1, rec_type, request_id, content_len,
        padding_len, 0)


def _read_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError("peer closed")
        buf += chunk
    return buf


def _read_name_value_len(data, pos):
    """A FastCGI name/value length is 1 byte (top bit clear) or 4 bytes,
    big-endian, with the top bit masked off (top bit set in the first
    byte)."""
    first = data[pos]
    if first & 0x80:
        n = struct.unpack("!I", data[pos:pos + 4])[0] & 0x7fffffff
        return n, pos + 4
    return first, pos + 1


def _parse_params(data):
    params = {}
    pos = 0
    while pos < len(data):
        nlen, pos = _read_name_value_len(data, pos)
        vlen, pos = _read_name_value_len(data, pos)
        name = data[pos:pos + nlen].decode('latin-1')
        pos += nlen
        value = data[pos:pos + vlen].decode('latin-1')
        pos += vlen
        params[name] = value
    return params


def _body_of_len(n):
    """`n` bytes of filler, ending in BODY_MARKER when there's room for it,
    so a test can still check for it even in a large/boundary-sized body."""
    if n <= len(BODY_MARKER):
        return (BODY_MARKER * ((n // len(BODY_MARKER)) + 1))[:n]
    filler = b"x" * (n - len(BODY_MARKER))
    return filler + BODY_MARKER


_REASON = {"200": "OK", "401": "Unauthorized", "403": "Forbidden"}


def _response_for(params):
    status = params.get("HTTP_X_TEST_STATUS", "401")
    case = params.get("HTTP_X_TEST_CASE", "split-headers-body")
    bodylen = int(params.get("HTTP_X_TEST_BODYLEN", str(len(BODY_MARKER))))
    reason = _REASON.get(status, "Status")

    headers = (f"Status: {status} {reason}\r\n"
               f"Content-Type: text/plain\r\n"
               f"\r\n").encode()
    body = _body_of_len(bodylen)
    hlen = len(headers)

    if case == "one-record":
        splits = []
    elif case == "multi-chunk-body":
        third = max(1, len(body) // 3)
        splits = [hlen, hlen + third, hlen + 2 * third]
    elif case == "split-headers":
        # split inside the header block, before the blank-line terminator
        splits = [max(1, hlen - 4)]
    else:
        # "split-headers-body" and "ignored-200": headers, then body
        splits = [hlen]

    full = headers + body
    return full, splits


def _send_split(conn, request_id, full, splits):
    prev = 0
    for off in list(splits) + [len(full)]:
        chunk = full[prev:off]
        prev = off
        if chunk:
            conn.sendall(_header(FCGI_STDOUT, request_id, len(chunk)) + chunk)
    conn.sendall(_header(FCGI_STDOUT, request_id, 0))  # end-of-stream


def _handle(conn):
    try:
        while True:
            hdr = _read_exact(conn, 8)
            _version, rtype, request_id, clen, plen, _reserved = \
                struct.unpack("!BBHHBB", hdr)
            assert rtype == FCGI_BEGIN_REQUEST
            _read_exact(conn, clen + plen)  # begin-request body + padding

            # FCGI_PARAMS records, until the empty (contentLength == 0)
            # terminator record.
            params_data = b""
            while True:
                hdr = _read_exact(conn, 8)
                _version, rtype, _rid, clen, plen, _reserved = \
                    struct.unpack("!BBHHBB", hdr)
                assert rtype == FCGI_PARAMS
                if clen:
                    params_data += _read_exact(conn, clen)
                    if plen:
                        _read_exact(conn, plen)
                else:
                    break

            params = _parse_params(params_data)
            full, splits = _response_for(params)
            _send_split(conn, request_id, full, splits)

            end_request_body = struct.pack("!IBxxx", 0, FCGI_REQUEST_COMPLETE)
            conn.sendall(
                _header(FCGI_END_REQUEST, request_id, len(end_request_body))
                + end_request_body)
    except EOFError:
        pass
    finally:
        conn.close()


def start(port=0):
    """Start the fake authorizer in a background thread. Returns the
    (srv, port) actually bound to, so port=0 can be used to pick a free
    one. A single connection is handled as a sequence of requests (the
    repeated-request case), each producing its own response per
    _response_for(); concurrent requests get their own connection/thread."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    bound_port = srv.getsockname()[1]

    def _serve():
        while True:
            try:
                conn, _addr = srv.accept()
            except OSError:
                return
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()

    threading.Thread(target=_serve, daemon=True).start()
    return srv, bound_port
