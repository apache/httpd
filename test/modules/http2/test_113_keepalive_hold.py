#
# mod-h2 test suite
# check that a stream finishing in the "hold" state (c1 done, c2 still
# running) does not make the connection declare KeepAlive while that
# stream is still unaccounted for (BZ 70302)
#
import re
import socket
import ssl
import threading
import time

import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported(), reason="mod_http2 not supported here")
class TestKeepaliveHold:

    PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    FRAME_HEADERS = 0x01
    FLAG_END_STREAM = 0x01
    FLAG_END_HEADERS = 0x04

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env, extras={
            'base': [
                "KeepAliveTimeout 1",
                "LogLevel core:warn http2:trace3",
            ]
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    @staticmethod
    def _frame(ftype, flags, stream_id, payload=b''):
        return (len(payload).to_bytes(3, 'big') + bytes([ftype, flags])
                + stream_id.to_bytes(4, 'big') + payload)

    @staticmethod
    def _hpack_literal(name: bytes, value: bytes) -> bytes:
        # literal header field never indexed, no Huffman: 0x00 prefix,
        # then length-prefixed name and value (RFC 7541 section 6.2.3)
        return bytes([0x00, len(name)]) + name + bytes([len(value)]) + value

    def _headers_block(self, authority: str, path: str) -> bytes:
        return (self._hpack_literal(b':method', b'GET')
                + self._hpack_literal(b':scheme', b'https')
                + self._hpack_literal(b':path', path.encode())
                + self._hpack_literal(b':authority', authority.encode()))

    @staticmethod
    def _recv_exact(sock, n) -> bytes:
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def _read_frames_until_done(self, sock, stream_ids, deadline):
        """Read frames until every stream in *stream_ids* has seen
        END_STREAM, or *deadline* (a monotonic time) passes."""
        remaining = set(stream_ids)
        sock.settimeout(1)
        while remaining and time.monotonic() < deadline:
            try:
                head = self._recv_exact(sock, 9)
            except socket.timeout:
                continue
            if len(head) < 9:
                break
            length = int.from_bytes(head[0:3], 'big')
            flags = head[4]
            sid = int.from_bytes(head[5:9], 'big') & 0x7fffffff
            self._recv_exact(sock, length)
            if flags & self.FLAG_END_STREAM:
                remaining.discard(sid)

    def _burst_and_idle(self, env, ctx, authority: str, n_streams: int, idle_s: float):
        """Open one h2 connection, fire *n_streams* concurrent GET requests
        for the same, trivially fast resource, wait for all of them to
        complete, then idle on the still-open connection."""
        with socket.create_connection(('localhost', int(env.https_port)), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname='localhost') as sock:
                assert sock.selected_alpn_protocol() == 'h2'
                out = bytearray(self.PREFACE)
                out += self._frame(0x04, 0, 0)  # empty SETTINGS
                stream_ids = list(range(1, 2 * n_streams, 2))
                for sid in stream_ids:
                    block = self._headers_block(authority, '/')
                    out += self._frame(self.FRAME_HEADERS,
                                       self.FLAG_END_HEADERS | self.FLAG_END_STREAM,
                                       sid, block)
                sock.sendall(bytes(out))
                self._read_frames_until_done(sock, stream_ids,
                                             time.monotonic() + 5)
                # idle on the connection: this is where a held stream
                # would, pre-fix, get stuck until KeepAliveTimeout
                time.sleep(idle_s)

    @staticmethod
    def _tls_context():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2'])
        return ctx

    @staticmethod
    def _burn_cpu(stop_event):
        while not stop_event.is_set():
            x = 0
            for i in range(100000):
                x += i * i

    # A stream whose c1 side finishes while its c2 is still wrapping up
    # (moved into m->shold) must never let the connection declare
    # KeepAlive before that stream is actually done: nothing wakes the
    # connection out of KeepAliveTimeout to finish it otherwise, so its
    # completion (and its access log entry) would be stuck for up to
    # KeepAliveTimeout.
    #
    # The race is inherently timing-dependent (it needs a c2 worker
    # thread to finish at the same moment c1 is evaluating whether to
    # go idle), so this does not force it on every round. Instead it
    # runs enough concurrent, back-to-back rounds -- with some CPU load
    # to perturb thread scheduling, as in the original report -- to
    # reliably exercise the "hold" path at least a few times, and
    # asserts the one invariant that must hold regardless: a
    # "keepalive=1" decision is never logged while any stream on that
    # connection is still sitting in the hold set.
    def test_h2_113_01_no_keepalive_while_held(self, env):
        host = f"test1.{env.http_tld}"
        ctx = self._tls_context()
        start_pos = env.httpd_error_log.current_pos()

        stop_event = threading.Event()
        burners = [threading.Thread(target=self._burn_cpu, args=(stop_event,),
                                    daemon=True)
                   for _ in range(2)]
        for b in burners:
            b.start()
        try:
            for _ in range(60):
                self._burst_and_idle(env, ctx, host, n_streams=8, idle_s=0.3)
        finally:
            stop_event.set()

        held = 0       # streams moved into the hold set
        resolved = 0    # of those, how many were later seen leaving it
        bad = 0         # keepalive=1 logged while one was still held
        re_hold = re.compile(r'.*move to shold')
        re_resolved = re.compile(r'.*(?:c2_done, in hold|already in spurge)')
        re_keepalive1 = re.compile(r'.*process returns, keepalive=1')
        with open(env.httpd_error_log.path) as fd:
            fd.seek(start_pos)
            pending = 0
            for line in fd:
                if re_hold.match(line):
                    held += 1
                    pending += 1
                elif re_resolved.match(line):
                    if pending > 0:
                        pending -= 1
                        resolved += 1
                elif re_keepalive1.match(line):
                    if pending > 0:
                        bad += 1

        assert held > 0, \
            "test did not exercise the hold path at all (held == 0); " \
            "increase rounds/load rather than treating this as a pass"
        assert bad == 0, \
            f"{bad} 'keepalive=1' decision(s) logged while a stream was " \
            f"still in the hold set ({held} held, {resolved} resolved)"
