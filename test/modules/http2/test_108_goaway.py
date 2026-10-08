#
# mod-h2 test suite
# check the error code of GOAWAY frames sent by the server
#
import socket
import ssl
import struct

import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported(), reason="mod_http2 not supported here")
class TestGoaway:

    PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    FRAME_SETTINGS = 0x04
    FRAME_GOAWAY = 0x07
    # error codes of RFC 9113, section 7
    ERR_NO_ERROR = 0x00
    ERR_INADEQUATE_SECURITY = 0x0c
    ERR_HTTP_1_1_REQUIRED = 0x0d

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env, extras={
            'base': [
                "AcceptFilter http none",
                "Timeout 1",
                "KeepAliveTimeout 1",
                "SSLCipherSuite HIGH:!aNULL",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0

    @staticmethod
    def _frame(ftype, payload=b''):
        # length, type, flags and the stream id 0
        return len(payload).to_bytes(3, 'big') + bytes([ftype, 0]) + bytes(4) + payload

    @staticmethod
    def _recv_exact(sock, n):
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def _goaway_error(self, env, ctx):
        """Open a connection, send the client preface and return the error
        code of the first GOAWAY frame the server sends, None if there is none."""
        with socket.create_connection(('localhost', int(env.https_port)), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname='localhost') as sock:
                assert sock.selected_alpn_protocol() == 'h2'
                sock.sendall(self.PREFACE + self._frame(self.FRAME_SETTINGS))
                while True:
                    head = self._recv_exact(sock, 9)
                    if len(head) < 9:
                        return None
                    length = int.from_bytes(head[0:3], 'big')
                    payload = self._recv_exact(sock, length)
                    if head[3] == self.FRAME_GOAWAY:
                        return struct.unpack('>II', payload[:8])[1]

    @staticmethod
    def _tls_context(ciphers=None, tls12_only=False):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2'])
        if tls12_only:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        if ciphers:
            ctx.set_ciphers(ciphers)
        return ctx

    # An idle connection that runs into the server timeout is closed
    # gracefully. The GOAWAY must carry NO_ERROR and not the APR status
    # of the timeout.
    def test_h2_108_01_idle_timeout(self, env):
        error = self._goaway_error(env, self._tls_context())
        assert error == self.ERR_NO_ERROR, f"GOAWAY error code {error}"

    # A TLS connection that is not acceptable for HTTP/2 is refused with
    # INADEQUATE_SECURITY (RFC 9113, section 9.2.1).
    def test_h2_108_02_inadequate_security(self, env):
        try:
            ctx = self._tls_context(ciphers='AES128-SHA256', tls12_only=True)
            error = self._goaway_error(env, ctx)
        except ssl.SSLError as ex:
            pytest.skip(f"cipher not available: {ex}")
        assert error == self.ERR_INADEQUATE_SECURITY, f"GOAWAY error code {error}"
