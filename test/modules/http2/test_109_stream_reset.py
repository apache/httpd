#
# mod-h2 test suite
# check that the reset of a stream by the client does not affect the connection
#
import socket
import struct
import time

import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported(), reason="mod_http2 not supported here")
class TestStreamReset:

    PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    DATA, HEADERS, RST_STREAM, SETTINGS, PING, GOAWAY = 0, 1, 3, 4, 6, 7
    END_STREAM, ACK, END_HEADERS = 0x1, 0x1, 0x4
    ERR_CANCEL = 0x08

    @staticmethod
    def _frame(ftype, flags=0, stream_id=0, payload=b''):
        return (len(payload).to_bytes(3, 'big') + bytes([ftype, flags])
                + struct.pack('>I', stream_id) + payload)

    def _get(self, stream_id, authority, path):
        # :method GET and :scheme http from the static table, :path and
        # :authority as literals without indexing, indexed name, no huffman
        block = (b'\x82\x86'
                 + bytes([0x04, len(path)]) + path.encode()
                 + bytes([0x01, len(authority)]) + authority.encode())
        return self._frame(self.HEADERS, self.END_STREAM | self.END_HEADERS,
                           stream_id, block)

    # The client resets a stream whose response is ready, but not yet sent.
    #
    # The server waits before it reads from the connection. It has then
    # queued the response HEADERS of the stream when it reads the RST_STREAM
    # of the client. nghttp2 can no longer send the HEADERS of the closed
    # stream and reports that. This is a normal race and must neither
    # affect the connection nor the other streams.
    #
    # The PINGs of the client keep the server busy, so that it handles
    # the events of the streams before it reads from the connection.
    def test_h2_109_01_reset_with_response_pending(self, env):
        conf = H2Conf(env, extras={
            'base': [
                "AcceptFilter http none",
                "Timeout 30",
                "H2TestC1ReadDelay 100ms",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0

        authority = f"cgi.{env.http_tld}"
        sock = socket.create_connection(('localhost', int(env.http_port)))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(self.PREFACE + self._frame(self.SETTINGS))
        sock.setblocking(False)
        goaway, finished, buf = None, set(), b''
        started = time.monotonic()
        sock.sendall(self._get(1, authority, "/h2test/error?delay=150ms"))
        reset_sent, next_ping, deadline = False, 0.0, started + 15
        request_sent = False
        try:
            while goaway is None and time.monotonic() < deadline:
                now = time.monotonic() - started
                if not reset_sent and now >= 0.340:
                    sock.sendall(self._frame(self.RST_STREAM, 0, 1,
                                             struct.pack('>I', self.ERR_CANCEL)))
                    reset_sent = True
                elif reset_sent and not request_sent and now >= 0.600:
                    sock.sendall(self._get(3, authority, "/h2test/error?delay=0ms"))
                    request_sent = True
                elif now >= next_ping:
                    sock.sendall(self._frame(self.PING, 0, 0, b'12345678'))
                    next_ping = now + 0.020
                if 3 in finished:
                    break
                try:
                    data = sock.recv(65536)
                    if not data:
                        break
                    buf += data
                except BlockingIOError:
                    time.sleep(0.001)
                while len(buf) >= 9:
                    length = int.from_bytes(buf[0:3], 'big')
                    if len(buf) < 9 + length:
                        break
                    ftype, flags = buf[3], buf[4]
                    stream_id = struct.unpack('>I', buf[5:9])[0] & 0x7fffffff
                    payload = buf[9:9 + length]
                    buf = buf[9 + length:]
                    if ftype == self.GOAWAY:
                        goaway = struct.unpack('>II', payload[:8])[1]
                    elif ftype == self.SETTINGS and not flags & self.ACK:
                        sock.sendall(self._frame(self.SETTINGS, self.ACK))
                    elif ftype in (self.HEADERS, self.DATA) and flags & self.END_STREAM:
                        finished.add(stream_id)
        finally:
            sock.close()
        assert goaway is None, f"GOAWAY error code {goaway}"
        assert 3 in finished, "no response on the connection after the stream reset"
