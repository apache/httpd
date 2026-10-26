r"""mpm_motorz: connection ids.

c->id names the worker slot running a connection (child * ThreadLimit + slot), as
in the worker and event MPMs.  mod_cgid keeps one entry per id and assumes the
ids stay within the number of worker slots.

The id is read back from mod_unique_id, whose last four bytes are c->id.
"""

import base64
import socket
import sys

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
