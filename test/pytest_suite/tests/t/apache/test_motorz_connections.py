r"""mpm_motorz: connection ids.

c->id names the worker slot running a connection (child * ThreadLimit + slot), as
in the worker and event MPMs.  mod_cgid keeps one entry per id and assumes the
ids stay within the number of worker slots.  The child also holds a limited
number of connections, whether or not they use a worker.

The id is read back from mod_unique_id, whose last four bytes are c->id.
"""

import base64
import socket
import sys
import time

import pytest

from apache_pytest.private_server import PrivateServer

THREADS = 4
CHILDREN = 2


def unique_id_conn_id(uid):
    raw = base64.urlsafe_b64decode(uid + "=" * (-len(uid) % 4))
    return int.from_bytes(raw[-4:], "big")


def request_id(port, path="/small.txt"):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(f"GET {path} HTTP/1.0\r\n\r\n".encode())
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    head = data.partition(b"\r\n\r\n")[0].decode()
    for line in head.split("\r\n"):
        if line.lower().startswith("x-uid:"):
            return unique_id_conn_id(line.split(":", 1)[1].strip())
    raise AssertionError(f"no X-Uid header in {head!r}")


@pytest.mark.skipif(sys.platform == "win32", reason="forking MPM")
def test_connection_ids_stay_within_the_worker_slots(config, tmp_path):
    if config.info.mpm != "motorz":
        pytest.skip("motorz only")
    if not (config.info.has_module("unique_id") and config.info.has_module("headers")):
        pytest.skip("needs mod_unique_id and mod_headers")

    extra = [
        f"StartServers {CHILDREN}",
        f"ThreadLimit {THREADS}",
        f"ThreadsPerChild {THREADS}",
        "ServerLimit 4",
        'Header always set X-Uid "%{UNIQUE_ID}e"',
    ]
    with PrivateServer(config, tmp_path, extra=extra, big_length=1024) as server:
        ids = [request_id(server.port) for _ in range(200)]

    limit = 4 * THREADS     # ServerLimit * ThreadLimit
    assert max(ids) < limit, f"id {max(ids)} outside the {limit} worker slots"


def served(sock, wait):
    """True once a 200 response to the request already sent on sock arrives."""
    sock.settimeout(wait)
    try:
        return sock.recv(4096).startswith(b"HTTP/1.1 200")
    except OSError:
        return False


@pytest.mark.skipif(sys.platform == "win32", reason="forking MPM")
def test_connections_are_limited_per_child(config, tmp_path):
    """Idle keep-alive connections use no worker, so the workers cannot limit
    them.  With 4 workers and AsyncRequestWorkerFactor 1 the child holds about
    4 + 4 connections; the rest wait in the listen backlog until room is made."""
    if config.info.mpm != "motorz":
        pytest.skip("motorz only")

    extra = ["StartServers 1", "ThreadsPerChild 4", "AsyncRequestWorkerFactor 1",
             "KeepAliveTimeout 120"]
    total = 40
    socks = []
    with PrivateServer(config, tmp_path, extra=extra, big_length=1024) as server:
        try:
            for _ in range(total):
                s = socket.create_connection(("127.0.0.1", server.port), timeout=10)
                s.sendall(b"GET /small.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
                socks.append(s)
            time.sleep(1)
            first = [s for s in socks if served(s, 0.2)]
            assert 4 <= len(first) <= 12, f"{len(first)} of {total} connections accepted"

            # Room is made when some of them go away, and is filled again.
            rest = [s for s in socks if s not in first]
            for s in first:
                s.close()
            deadline = time.monotonic() + 15
            second = []
            while time.monotonic() < deadline and len(second) < len(first):
                second += [s for s in rest if s not in second and served(s, 0.2)]
            assert len(second) >= len(first) // 2, \
                f"{len(second)} waiting connections served after {len(first)} closed"
            time.sleep(1)
            second += [s for s in rest if s not in second and served(s, 0.2)]
            assert len(second) <= 12, f"{len(second)} connections held after the restart of accepting"
        finally:
            for s in socks:
                s.close()


@pytest.mark.skipif(sys.platform == "win32", reason="forking MPM")
def test_connections_of_a_protocol_that_sets_no_state_are_closed(config, tmp_path):
    """mod_echo returns OK from process_connection without setting a connection
    state.  Such a connection must be closed when the client leaves; if it is
    not, it counts against the connection limit for ever and the child stops
    accepting."""
    if config.info.mpm != "motorz":
        pytest.skip("motorz only")
    if not config.info.has_module("echo"):
        pytest.skip("needs mod_echo")

    extra = ["StartServers 1", "ThreadsPerChild 4", "AsyncRequestWorkerFactor 1",
             "ProtocolEcho On"]
    with PrivateServer(config, tmp_path, extra=extra, big_length=1024) as server:
        results = []
        for _ in range(20):             # more than the limit of 8
            with socket.create_connection(("127.0.0.1", server.port), timeout=3) as s:
                s.sendall(b"hi\r\n")
                try:
                    results.append(s.recv(100) == b"hi\r\n")
                except OSError:
                    results.append(False)
    assert all(results), "".join("Y" if r else "n" for r in results)
