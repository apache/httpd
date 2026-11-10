"""A small synchronous HTTP/3 client on top of aioquic, for the tests."""
import asyncio
import json
import time
from typing import List, Optional, Tuple

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamReset


class H3Response:

    def __init__(self, stream_id: int):
        self.stream_id = stream_id
        self.headers: List[Tuple[bytes, bytes]] = []
        self.trailers: List[Tuple[bytes, bytes]] = []
        self.body = b""
        self.data_times: List[float] = []
        self.reset: Optional[int] = None
        self.terminated: Optional[ConnectionTerminated] = None
        self.started = time.monotonic()

    @property
    def status(self) -> Optional[int]:
        v = self.header(":status")
        return int(v) if v is not None else None

    def header_values(self, name: str) -> List[str]:
        n = name.lower().encode()
        return [v.decode() for k, v in self.headers if k == n]

    def header(self, name: str) -> Optional[str]:
        values = self.header_values(name)
        return values[0] if values else None

    @property
    def text(self) -> str:
        return self.body.decode()

    @property
    def json(self):
        return json.loads(self.body)

    def __repr__(self):
        return (f"H3Response[sid={self.stream_id}, status={self.status}, "
                f"reset={self.reset}, terminated={self.terminated}, "
                f"headers={self.headers}, body={self.body[:200]!r}]")


class _Protocol(QuicConnectionProtocol):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.pending = {}
        self.terminated = None

    def _finish(self, sid):
        resp, fut = self.pending.pop(sid)
        if not fut.done():
            fut.set_result(resp)

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self.terminated = event
            for sid in list(self.pending):
                self.pending[sid][0].terminated = event
                self._finish(sid)
        if isinstance(event, StreamReset) and event.stream_id in self.pending:
            self.pending[event.stream_id][0].reset = event.error_code
            self._finish(event.stream_id)
            return
        for ev in self.http.handle_event(event):
            if ev.stream_id not in self.pending:
                continue
            resp = self.pending[ev.stream_id][0]
            if isinstance(ev, HeadersReceived):
                if resp.headers:
                    resp.trailers.extend(ev.headers)
                else:
                    resp.headers.extend(ev.headers)
            elif isinstance(ev, DataReceived):
                if ev.data:
                    resp.body += ev.data
                    resp.data_times.append(time.monotonic())
            if getattr(ev, "stream_ended", False):
                self._finish(ev.stream_id)

    def send_request(self, method, path, authority, headers, body):
        sid = self._quic.get_next_available_stream_id()
        hdrs = [(b":method", method.encode()), (b":scheme", b"https"),
                (b":authority", authority.encode()), (b":path", path.encode())]
        hdrs.extend((k.lower().encode(), v.encode()) for k, v in headers)
        self.http.send_headers(sid, hdrs, end_stream=body is None)
        if body is not None:
            self.http.send_data(sid, body, end_stream=True)
        fut = asyncio.get_running_loop().create_future()
        self.pending[sid] = (H3Response(sid), fut)
        self.transmit()
        return fut


class H3Client:
    """Each call opens one QUIC connection and closes it when done."""

    def __init__(self, env, domain: str = None, port: int = None,
                 server_name: str = None, client_cert=None,
                 session_ticket=None, timeout: float = 10):
        self.env = env
        self.domain = domain or env.h3_domain
        self.port = port or env.https_port
        self.server_name = server_name or self.domain
        self.client_cert = client_cert
        self.session_ticket = session_ticket
        self.timeout = timeout
        self.received_tickets = []

    def _config(self) -> QuicConfiguration:
        cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                server_name=self.server_name,
                                session_ticket=self.session_ticket)
        cfg.load_verify_locations(self.env.ca.cert_file)
        if self.client_cert:
            cfg.load_cert_chain(self.client_cert.cert_file,
                                self.client_cert.pkey_file)
        return cfg

    async def _run(self, reqs, sequential):
        async with connect("127.0.0.1", self.port, configuration=self._config(),
                           create_protocol=_Protocol,
                           session_ticket_handler=self.received_tickets.append) as proto:
            results = []
            if sequential:
                for r in reqs:
                    results.append(await asyncio.wait_for(
                        proto.send_request(**r), self.timeout))
            else:
                futs = [proto.send_request(**r) for r in reqs]
                results = await asyncio.wait_for(asyncio.gather(*futs),
                                                 self.timeout)
            return results

    def _req(self, method="GET", path="/", headers=None, body=None,
             authority=None):
        return dict(method=method, path=path, headers=headers or [],
                    body=body, authority=authority or f"{self.domain}:{self.port}")

    def requests(self, reqs: List[dict], sequential=False) -> List[H3Response]:
        """Several requests on one connection; each a dict of request() args."""
        return asyncio.run(self._run([self._req(**r) for r in reqs], sequential))

    def request(self, method="GET", path="/", headers=None, body=None,
                authority=None) -> H3Response:
        return self.requests([dict(method=method, path=path, headers=headers,
                                   body=body, authority=authority)])[0]

    def get(self, path="/", **kwargs) -> H3Response:
        return self.request("GET", path, **kwargs)
