import base64
import os
import socket
import struct
import textwrap
import time

import pytest

from pyhttpd.conf import HttpdConf


# Payload per frame, and how many to send: 4096 x 32KiB.  Each frame
# is paced by a "sync" round trip and fits in one loopback segment:
# r:wsread() fails on a frame which has only partly arrived.
FRAME_SIZE = 32 * 1024
FRAME_COUNT = 4096


@pytest.mark.skipif(not os.path.exists("/proc/self/status"),
                    reason="needs /proc/self/status")
class TestWebsocket:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.require(env.has_shared_module("lua"), "mod_lua not built",
                    dep="mod_lua")
        conf = HttpdConf(env, extras={
            'base': textwrap.dedent(f"""
            <Directory "{env.server_docs_dir}/test1/lua">
                SetHandler lua-script
            </Directory>
            """),
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    @staticmethod
    def frame(payload: bytes, opcode=0x2, masked=True) -> bytes:
        # A client frame; an all-zero mask leaves the payload as is.
        n = len(payload)
        m = 0x80 if masked else 0
        if n < 126:
            hdr = struct.pack("!BB", 0x80 | opcode, m | n)
        elif n < 65536:
            hdr = struct.pack("!BBH", 0x80 | opcode, m | 126, n)
        else:
            hdr = struct.pack("!BBQ", 0x80 | opcode, m | 127, n)
        return hdr + (b"\0\0\0\0" if masked else b"") + payload

    @staticmethod
    def recv_exact(sock, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            assert chunk, f"connection closed after {len(buf)}/{n} bytes"
            buf += chunk
        return buf

    def recv_opcode_frame(self, sock):
        b0, b1 = self.recv_exact(sock, 2)
        n = b1 & 0x7f
        if n == 126:
            n, = struct.unpack("!H", self.recv_exact(sock, 2))
        elif n == 127:
            n, = struct.unpack("!Q", self.recv_exact(sock, 8))
        return b0 & 0xf, self.recv_exact(sock, n)

    def recv_frame(self, sock) -> bytes:
        return self.recv_opcode_frame(sock)[1]

    def sync(self, sock) -> bytes:
        sock.sendall(self.frame(b"sync", opcode=0x1))
        return self.recv_frame(sock)

    def rss(self, sock) -> int:
        sock.sendall(self.frame(b"rss", opcode=0x1))
        return int(self.recv_frame(sock))

    def upgrade(self, env):
        sock = socket.create_connection((env.http_addr, env.http_port),
                                        timeout=30)
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall((f"GET /lua/wsread.lua HTTP/1.1\r\n"
                      f"Host: test1.{env.http_tld}:{env.http_port}\r\n"
                      f"Upgrade: websocket\r\n"
                      f"Connection: Upgrade\r\n"
                      f"Sec-WebSocket-Key: {key}\r\n"
                      f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(1)
            assert chunk, f"connection closed in response head: {head!r}"
            head += chunk
        assert head.startswith(b"HTTP/1.1 101 "), head
        return sock

    # r:wsread() caps its memory use: nothing it allocates for a frame
    # outlives the call, so memory use does not scale with the number
    # of frames read.
    @pytest.mark.skipif("TEST_ASAN" in os.environ,
                        reason="RSS is not a measure of memory use under ASan")
    def test_lua_001_01_wsread_memory(self, env):
        sock = self.upgrade(env)
        try:
            before = self.rss(sock)
            payload = b"x" * FRAME_SIZE
            data = self.frame(payload) + self.frame(b"sync", opcode=0x1)
            for _ in range(FRAME_COUNT):
                sock.sendall(data)
                assert self.recv_frame(sock) == b"ok"
            after = self.rss(sock)
        finally:
            sock.close()
        sent_kb = FRAME_SIZE * FRAME_COUNT // 1024
        growth_kb = after - before
        assert growth_kb < sent_kb // 4, \
            f"child RSS grew {growth_kb}kB ({before}kB -> {after}kB) " \
            f"reading {sent_kb}kB of websocket frames"

    # A frame which arrives in two parts is still read whole.
    def test_lua_001_02_partial_frame(self, env):
        sock = self.upgrade(env)
        try:
            data = self.frame(b"sync", opcode=0x1)
            sock.sendall(data[:-2])
            time.sleep(0.5)
            sock.sendall(data[-2:])
            assert self.recv_frame(sock) == b"ok"
        finally:
            sock.close()

    # A frame larger than one socket read, sent without pacing.
    def test_lua_001_03_large_frame(self, env):
        sock = self.upgrade(env)
        try:
            sock.sendall(self.frame(b"x" * 7 * 1024 * 1024))
            assert self.sync(sock) == b"ok"
        finally:
            sock.close()

    # RFC 6455 5.5.3: a Pong echoes the Ping's application data.
    def test_lua_001_04_ping_payload(self, env):
        sock = self.upgrade(env)
        try:
            sock.sendall(self.frame(b"hello", opcode=0x9))
            assert self.recv_opcode_frame(sock) == (0xa, b"hello")
            assert self.sync(sock) == b"ok"
        finally:
            sock.close()

    # An empty message is a message, not the end of the connection.
    def test_lua_001_05_empty_frame(self, env):
        sock = self.upgrade(env)
        try:
            sock.sendall(self.frame(b"", opcode=0x1))
            assert self.sync(sock) == b"ok"
        finally:
            sock.close()

    # RFC 6455 5.1: the server closes the connection on an unmasked
    # client frame.
    def test_lua_001_06_unmasked_frame(self, env):
        sock = self.upgrade(env)
        try:
            sock.sendall(self.frame(b"sync", opcode=0x1, masked=False))
            sock.settimeout(5)
            data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pytest.fail(f"connection left open, received {data!r}")
            assert b"ok" not in data, data
        finally:
            sock.close()

    # r:wspeek() is false with nothing to read.
    def test_lua_001_07_wspeek_empty(self, env):
        sock = self.upgrade(env)
        try:
            sock.sendall(self.frame(b"peek", opcode=0x1))
            assert self.recv_frame(sock) == b"false"
        finally:
            sock.close()

    # r:wspeek() does not consume what it finds.
    def test_lua_001_08_wspeek_read(self, env):
        sock = self.upgrade(env)
        try:
            sock.sendall(self.frame(b"peekread", opcode=0x1))
            time.sleep(0.5)
            sock.sendall(self.frame(b"hello", opcode=0x1))
            assert self.recv_frame(sock) == b"hello"
        finally:
            sock.close()
