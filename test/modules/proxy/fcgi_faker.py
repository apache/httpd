"""
Minimal fake FastCGI responder for testing mod_proxy_fcgi.

Speaks just enough of the FastCGI record protocol to accept one request
(FCGI_BEGIN_REQUEST, FCGI_PARAMS..., empty FCGI_PARAMS, FCGI_STDIN..., empty
FCGI_STDIN) and answer with a JSON document of the CGI parameters it was
given, so tests can inspect what ProxyFCGISetEnvIf produced.
"""
import json
import socket
import struct

from .env import TCPFaker

FCGI_BEGIN_REQUEST = 1
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6


def _record(rtype, req_id, content):
    pad = (8 - len(content) % 8) % 8
    return struct.pack("!BBHHBx", 1, rtype, req_id, len(content), pad) \
        + content + b"\0" * pad


def _parse_params(data):
    params = {}
    pos = 0
    while pos < len(data):
        lens = []
        for _ in range(2):
            if data[pos] >> 7:
                lens.append(struct.unpack_from("!I", data, pos)[0] & 0x7fffffff)
                pos += 4
            else:
                lens.append(data[pos])
                pos += 1
        name = data[pos:pos + lens[0]].decode("latin-1")
        pos += lens[0]
        val = data[pos:pos + lens[1]].decode("latin-1")
        pos += lens[1]
        params[name] = val
    return params


class FCGIFaker(TCPFaker):

    def __init__(self, host, port):
        super().__init__(host, port)
        self.params = None

    def _handle(self, c):
        buf = b""
        params_raw = b""
        req_id = 1
        stdin_done = False
        while not stdin_done:
            data = c.recv(65536)
            if not data:
                break
            buf += data
            while len(buf) >= 8:
                _, rtype, rid, clen, plen = struct.unpack_from("!BBHHBx", buf, 0)
                if len(buf) < 8 + clen + plen:
                    break
                content = buf[8:8 + clen]
                buf = buf[8 + clen + plen:]
                req_id = rid
                if rtype == FCGI_PARAMS:
                    params_raw += content
                elif rtype == FCGI_STDIN and clen == 0:
                    stdin_done = True
                    break
        self.params = _parse_params(params_raw)
        body = json.dumps(self.params).encode()
        out = b"Content-Type: application/json\r\n\r\n" + body
        c.sendall(_record(FCGI_STDOUT, req_id, out)
                  + _record(FCGI_STDOUT, req_id, b"")
                  + _record(FCGI_END_REQUEST, req_id, struct.pack("!IBxxx", 0, 0)))

    def _process(self):
        while not self._done:
            try:
                c, _ = self._socket.accept()
                try:
                    self._handle(c)
                    try:
                        c.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                finally:
                    c.close()
            except socket.timeout:
                pass
            except ConnectionAbortedError:
                self._done = True
