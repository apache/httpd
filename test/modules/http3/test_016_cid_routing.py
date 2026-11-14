import os
import socket
import ssl
import sys
import time

import pytest

from aioquic.buffer import Buffer
from aioquic.h3.connection import H3_ALPN
from aioquic.quic import events as quic_events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import pull_quic_transport_parameters

from .env import H3Conf

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="SO_REUSEPORT buckets are Linux only")


class _Conn(QuicConnection):
    """Keeps the server transport parameters."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.server_params = None

    def _parse_transport_parameters(self, data, from_session_ticket=False):
        if not from_session_ticket:
            self.server_params = pull_quic_transport_parameters(Buffer(data=data))
        return super()._parse_transport_parameters(data, from_session_ticket)


class _Client:
    """A QUIC client on its own connected UDP socket, so it can change its local port."""

    def __init__(self, env):
        self.target = ("127.0.0.1", env.https_port)
        self.sock = self._socket()
        config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                   verify_mode=ssl.CERT_NONE, server_name=env.h3_domain)
        self.quic = _Conn(configuration=config)
        self.events = []
        self.done = False

    def _socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(self.target)
        s.settimeout(0.05)
        return s

    def run(self, seconds, until_done=True):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not (until_done and self.done):
            for data, _ in self.quic.datagrams_to_send(now=time.monotonic()):
                self.sock.send(data)
            try:
                data = self.sock.recv(65535)
            except (TimeoutError, socket.timeout):
                timer = self.quic.get_timer()
                if timer is not None and timer <= time.monotonic():
                    self.quic.handle_timer(now=time.monotonic())
                continue
            self.quic.receive_datagram(data, self.target, now=time.monotonic())
            while (event := self.quic.next_event()) is not None:
                self.events.append(event)
                if isinstance(event, quic_events.HandshakeCompleted):
                    self.done = True
        return self.done

    def handshake(self):
        self.quic.connect(self.target, now=time.monotonic())
        return self.run(5)

    def migrate(self):
        """Send from a new local port: a new 4-tuple, so a new kernel hash."""
        old, self.sock = self.sock, self._socket()
        old.close()

    def ping(self, uid, seconds=2):
        self.events.clear()
        self.quic.send_ping(uid)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.run(0.1, until_done=False)
            if any(isinstance(e, quic_events.PingAcknowledged) and e.uid == uid for e in self.events):
                return True
            if any(isinstance(e, quic_events.ConnectionTerminated) for e in self.events):
                return False
        return False

    def close(self):
        self.quic.close()
        self.run(0.2, until_done=False)
        self.sock.close()


class TestCidRouting:
    """With buckets, an eBPF program routes each packet by byte 0 of its connection ID."""

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        if env.h3_ossl_backend:
            pytest.skip("routing by connection ID needs the ngtcp2 backend")
        cpus = os.cpu_count() or 1
        if cpus < 2:
            pytest.skip("two buckets need two cores")
        H3Conf(env).add(f"ListenCoresBucketsRatio {cpus // 2}").add_h3_vhost().install()
        assert env.apache_restart() == 0
        assert env.wait_udp_port(env.https_port)

    def _client(self, env):
        c = _Client(env)
        assert c.handshake()
        return c

    @staticmethod
    def _routed(c):
        return not c.quic.server_params.disable_active_migration

    # Without routing (no CAP_BPF, kernel before 4.19, SELinux, seccomp) the
    # server keeps the kernel hash and tells clients not to migrate.
    def test_h3_016_01_migration_flag_matches_routing(self, env):
        c = self._client(env)
        with open(os.path.join(env.server_logs_dir, "error_log")) as f:
            log = f.read()
        routed = self._routed(c)
        c.close()
        if routed:
            assert "packets routed by connection ID" in log
        else:
            assert "QUIC routing by connection ID is off" in log
            env.httpd_error_log.ignore_recent(matches=[r'.*QUIC routing by connection ID is off'])

    def test_h3_016_02_server_cids_carry_one_bucket(self, env):
        c = self._client(env)
        if not self._routed(c):
            c.close()
            pytest.skip("routing by connection ID is off here")
        c.run(0.5, until_done=False)  # NEW_CONNECTION_ID frames follow the handshake
        cids = [c.quic._peer_cid.cid] + [p.cid for p in c.quic._peer_cid_available]
        c.close()
        assert len(cids) > 1, "the server issued no new connection IDs"
        assert len({cid[0] for cid in cids}) == 1, [cid.hex() for cid in cids]

    def test_h3_016_03_connection_survives_migration(self, env):
        c = self._client(env)
        if not self._routed(c):
            c.close()
            pytest.skip("routing by connection ID is off here")
        # A client may migrate only after the handshake is confirmed (RFC 9000 section 9).
        assert c.ping(100), "no ack before migration"
        for i in range(6):
            c.migrate()
            if i == 5:
                c.quic.change_connection_id()  # a CID from NEW_CONNECTION_ID
            assert c.ping(i), f"migration {i + 1}: no answer, the packet reached another child"
        c.close()
