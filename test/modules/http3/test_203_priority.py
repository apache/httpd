"""Test that mod_http3 correctly handles RFC 9218 PRIORITY_UPDATE frames."""

import asyncio
import ssl

import pytest

from .env import H3Conf

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import encode_uint_var
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

FRAME_TYPE_PRIORITY_UPDATE_REQUEST_STREAM = 0xF0700


class _PriorityUpdateClient(QuicConnectionProtocol):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self.status = None
        self.body = b""
        self._done = asyncio.Event()

    def quic_event_received(self, event):
        for h3_event in self._http.handle_event(event):
            if isinstance(h3_event, HeadersReceived):
                for k, v in h3_event.headers:
                    if k == b":status":
                        self.status = v.decode()
                if h3_event.stream_ended:
                    self._done.set()
            elif isinstance(h3_event, DataReceived):
                self.body += h3_event.data
                if h3_event.stream_ended:
                    self._done.set()

    async def get_with_priority_update(
        self, authority: str, path: str, timeout: float = 5.0
    ):
        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)

        payload = encode_uint_var(stream_id)
        frame = (
            encode_uint_var(FRAME_TYPE_PRIORITY_UPDATE_REQUEST_STREAM)
            + encode_uint_var(len(payload))
            + payload
        )
        self._quic.send_stream_data(self._http._local_control_stream_id, frame)

        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
            ],
            end_stream=True,
        )
        self.transmit()
        await asyncio.wait_for(self._done.wait(), timeout=timeout)


class TestPriorityUpdate:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0

    def test_h3_203_01_priority_update_does_not_kill_connection(self, env):
        env.require(env.has_python_package("aioquic"),
                    "python package 'aioquic' is not installed",
                    dep="aioquic")
        authority = env.h3_domain

        async def run():
            config = QuicConfiguration(
                is_client=True,
                alpn_protocols=H3_ALPN,
                server_name=authority,
            )
            config.load_verify_locations(env.ca.cert_file)
            async with connect(
                "127.0.0.1",
                env.https_port,
                configuration=config,
                create_protocol=_PriorityUpdateClient,
            ) as client:
                await client.get_with_priority_update(authority, "/001.html")
                return client.status, client.body

        status, body = asyncio.run(run())
        assert status == "200", (
            "PRIORITY_UPDATE for a valid, in-range stream ID must not "
            "be treated as a protocol error"
        )
