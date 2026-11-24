"""Test that a response's header block never waits for its QPACK inserts."""

import asyncio
import itertools

import pylsqpack
import pytest

from .env import H3Conf

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

BATCH = 20
N_REQUESTS = 3000


class _CountingH3(H3Connection):
    """Counts header blocks that use the dynamic table, and those that
    reference an insert not received yet."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dynamic = 0
        self.blocked = 0

    def _decode_headers(self, stream_id, frame_data):
        # None when a blocked block is retried; a nonzero first byte is a
        # nonzero Required Insert Count (RFC 9204 4.5.1)
        if frame_data and frame_data[0] != 0:
            self.dynamic += 1
        try:
            return super()._decode_headers(stream_id, frame_data)
        except pylsqpack.StreamBlocked:
            self.blocked += 1
            raise


class _Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = _CountingH3(self._quic)
        self.headers = {}
        self.done = {}

    def quic_event_received(self, event):
        for ev in self.http.handle_event(event):
            if isinstance(ev, HeadersReceived):
                self.headers[ev.stream_id] = dict(ev.headers)
            if getattr(ev, "stream_ended", False) and ev.stream_id in self.done:
                self.done[ev.stream_id].set()

    def start_get(self, authority: str, path: str) -> int:
        sid = self._quic.get_next_available_stream_id()
        self.done[sid] = asyncio.Event()
        self.http.send_headers(sid, [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
        ], end_stream=True)
        return sid


class TestQpackOrder:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        # a new value per response: each header block needs a fresh insert
        H3Conf(env).add_h3_vhost(directives=[
            'Header always set Cache-Control "expr=max-age=%{QUERY_STRING}"',
        ]).install()
        assert env.apache_restart() == 0

    def test_h3_205_01_inserts_sent_before_header_blocks(self, env):
        env.require(env.has_python_package("aioquic"),
                    "python package 'aioquic' is not installed",
                    dep="aioquic")
        authority = env.h3_domain
        seq = itertools.count()

        async def run():
            config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                       server_name=authority)
            config.load_verify_locations(env.ca.cert_file)
            async with connect("127.0.0.1", env.https_port,
                               configuration=config,
                               create_protocol=_Client) as client:
                expected = {}
                for _ in range(N_REQUESTS // BATCH):
                    batch = []
                    for _ in range(BATCH):
                        n = next(seq)
                        sid = client.start_get(authority, f"/001.html?{n}")
                        expected[sid] = f"max-age={n}".encode()
                        batch.append(sid)
                    client.transmit()
                    await asyncio.wait_for(asyncio.gather(
                        *(client.done[sid].wait() for sid in batch)), 15)
                return client, expected

        client, expected = asyncio.run(run())
        for sid, value in expected.items():
            hdrs = client.headers.get(sid, {})
            assert hdrs.get(b":status") == b"200", f"stream {sid}: {hdrs}"
            assert hdrs.get(b"cache-control") == value, f"stream {sid}: {hdrs}"
        # Without the dynamic table (aioquic >= 1.8 turns it off) nothing can
        # be blocked, and the check below would pass whatever the server does.
        assert client.http.dynamic >= len(expected) // 2, \
            f"only {client.http.dynamic} of {len(expected)} header blocks " \
            f"used the QPACK dynamic table"
        # A header block sent ahead of the encoder stream data it depends on
        # stalls the stream, and a client that closes it then loses the response.
        assert client.http.blocked == 0, \
            f"{client.http.blocked} of {len(expected)} header blocks were blocked"
