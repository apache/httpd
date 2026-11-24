"""Test HTTP/3 stream multiplexing over a single connection."""

import asyncio
import ssl

import pytest

from .env import H3Conf

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

N_CONCURRENT_GETS = 20
POST_BODY_LEN = 100_000


class _MuxClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self.status = {}
        self.body = {}
        self.done = {}

    def quic_event_received(self, event):
        for h3_event in self._http.handle_event(event):
            sid = h3_event.stream_id
            if isinstance(h3_event, HeadersReceived):
                for k, v in h3_event.headers:
                    if k == b":status":
                        self.status[sid] = v.decode()
                if h3_event.stream_ended:
                    self.done[sid].set()
            elif isinstance(h3_event, DataReceived):
                self.body[sid] = self.body.get(sid, b"") + h3_event.data
                if h3_event.stream_ended:
                    self.done[sid].set()

    def start_get(self, authority: str, path: str) -> int:
        sid = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self.done[sid] = asyncio.Event()
        self._http.send_headers(
            stream_id=sid,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
            ],
            end_stream=True,
        )
        return sid

    def start_post(self, authority: str, path: str, body: bytes) -> int:
        sid = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self.done[sid] = asyncio.Event()
        self._http.send_headers(
            stream_id=sid,
            headers=[
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
                (b"content-length", str(len(body)).encode()),
            ],
            end_stream=False,
        )
        chunk_size = 4096
        for i in range(0, len(body), chunk_size):
            end = (i + chunk_size) >= len(body)
            self._http.send_data(sid, body[i : i + chunk_size], end)
        return sid


class TestStreamMultiplexing:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0

    def test_h3_204_01_many_concurrent_streams_one_connection(self, env):
        env.require(env.has_python_package("aioquic"),
                    "python package 'aioquic' is not installed",
                    dep="aioquic")
        authority = env.h3_domain

        async def run():
            config = QuicConfiguration(
                is_client=True, alpn_protocols=H3_ALPN,
                server_name=authority,
            )
            config.load_verify_locations(env.ca.cert_file)
            async with connect(
                "127.0.0.1", env.https_port, configuration=config,
                create_protocol=_MuxClient,
            ) as client:
                get_ids = [client.start_get(authority, "/001.html")
                           for _ in range(N_CONCURRENT_GETS)]
                post_body = bytes((i % 251) for i in range(POST_BODY_LEN))
                post_id = client.start_post(authority, "/upload-does-not-exist",
                                            post_body)
                client.transmit()

                await asyncio.wait_for(
                    asyncio.gather(*(client.done[sid].wait()
                                     for sid in [*get_ids, post_id])),
                    timeout=15,
                )
                return client, get_ids, post_id

        client, get_ids, post_id = asyncio.run(run())

        for sid in get_ids:
            assert client.status[sid] == "200", \
                f"stream {sid}: status={client.status.get(sid)}"

        assert client.status[post_id] in ("200", "404", "405")
