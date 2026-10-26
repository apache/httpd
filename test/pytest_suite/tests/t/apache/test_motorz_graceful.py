r"""mpm_motorz: a child told to stop gracefully finishes the connections it has.

The server delivers a large static file.  The client reads a little of it and
stops, so that the server fills the socket buffers and the connection is parked
in the MPM waiting to write.  Then the parent is sent the graceful restart
signal.  The old child must keep serving that connection until the whole body
has been delivered, while the new generation answers other requests.

The body has to come from the core handler: a handler that writes it itself
(mod_test_rwrite) blocks a worker thread for the whole transfer, and the
connection is then never parked, so the test passes even without the drain.

The tests run a private httpd: restarting the suite's own server would change
its state (its worker set, the log, ...) for the tests that run after this one.

A peer that keeps writing to a connection the server is closing must not keep
the old child alive: the lingering close has one fixed deadline.

A draining child keeps its process slot, and no replacement can start while
every slot is taken.  The other tests open a download, restart, and repeat, so
that several old children are draining at once, then check that new connections
are still served (default ServerLimit) and that the parent says so when they are
not (ServerLimit 2).
"""

import socket
import sys
import time

import pytest

from apache_pytest.private_server import (BODY_LENGTH, PrivateServer,
                                          child_pids, get, read_headers)


@pytest.mark.skipif(sys.platform == "win32", reason="signals")
def test_graceful_restart_does_not_cut_a_download(config, tmp_path):
    if config.info.mpm != "motorz":
        pytest.skip("motorz only")

    sock = None
    with PrivateServer(config, tmp_path) as server:
        try:
            sock = get(server.port, "/big.bin", rcvbuf=4096)
            head, body = read_headers(sock)
            assert b" 200 " in head.split(b"\r\n")[0], head
            received = len(body)

            # Let the server run into the closed window, then restart gracefully.
            time.sleep(1)
            server.graceful()

            # The new generation answers other requests while the old child drains.
            assert server.small_ok(20), "no response after the graceful restart"

            # The old child has had time to exit if it had dropped the connection.
            time.sleep(1)
            while chunk := sock.recv(65536):
                received += len(chunk)
        finally:
            if sock:
                sock.close()

    assert received == BODY_LENGTH


def open_downloads_across_restarts(server, rounds):
    """Park a download, restart gracefully, and repeat; return the sockets and
    whether /small.txt was served after the last restart."""
    socks = []
    served = True
    for _ in range(rounds):
        sock = get(server.port, "/big.bin", rcvbuf=4096)
        head, body = read_headers(sock)
        assert b" 200 " in head.split(b"\r\n")[0], head
        socks.append([sock, len(body)])
        time.sleep(1)               # the server fills the buffers and parks it
        server.graceful()
        served = server.small_ok(5)
    return socks, served


def finish_downloads(socks, big_length):
    for entry in socks:
        sock = entry[0]
        while chunk := sock.recv(65536):
            entry[1] += len(chunk)
        sock.close()
        assert entry[1] == big_length


@pytest.mark.skipif(sys.platform == "win32", reason="signals")
def test_restarts_with_open_downloads_do_not_starve_new_connections(config, tmp_path):
    """Each old child keeps its slot while its download runs.  With the default
    ServerLimit there is still room for the next generation, so a new request
    is served after every restart."""
    if config.info.mpm != "motorz":
        pytest.skip("motorz only")

    big = 16 * 1024 * 1024
    socks = []
    with PrivateServer(config, tmp_path, big_length=big) as server:
        try:
            socks, served = open_downloads_across_restarts(server, 3)
            assert served, "no child accepted a new connection after the restarts"
            assert "scoreboard is full" not in server.error_log()
        finally:
            for entry in socks:
                entry[0].close()


@pytest.mark.skipif(sys.platform == "win32", reason="signals")
def test_full_scoreboard_is_reported_once_and_recovers(config, tmp_path):
    """With ServerLimit 2 the second restart finds both slots held by draining
    children, so nothing can start.  The parent must say so, once, and serve
    again as soon as a draining child is done."""
    if config.info.mpm != "motorz":
        pytest.skip("motorz only")

    big = 16 * 1024 * 1024
    socks = []
    with PrivateServer(config, tmp_path, extra=["ServerLimit 2"],
                       big_length=big) as server:
        try:
            socks, _ = open_downloads_across_restarts(server, 2)
            # The parent checks the slots once a second; give it a few rounds.
            time.sleep(4)
            log = server.error_log()
            assert log.count("scoreboard is full") == 1, log

            finish_downloads(socks, big)
            socks = []
            assert server.small_ok(20), "no recovery after the downloads finished"
        finally:
            for entry in socks:
                entry[0].close()


@pytest.mark.skipif(sys.platform == "win32", reason="signals")
def test_trickle_input_does_not_extend_lingering_close(config, tmp_path):
    """The client sends one byte every 250 ms to a connection the server has
    finished with.  The linger deadline is fixed when the lingering close
    starts, so once a graceful restart shortens it the old child must be gone
    after a couple of seconds although the client never stops writing."""
    if config.info.mpm != "motorz":
        pytest.skip("motorz only")

    with PrivateServer(config, tmp_path) as server:
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        try:
            sock.sendall(b"GET /small.txt HTTP/1.1\r\nHost: localhost\r\n"
                         b"Connection: close\r\n\r\n")
            while sock.recv(4096):      # until the server shuts its side down
                pass

            old = child_pids(server.proc.pid)
            assert old, "no child process found"
            server.graceful()

            start = time.monotonic()
            gone = None
            while time.monotonic() - start < 15:
                try:
                    sock.send(b"x")
                except OSError:
                    pass                # the server may have closed already
                if not (old & child_pids(server.proc.pid)):
                    gone = time.monotonic() - start
                    break
                time.sleep(0.25)
            assert gone is not None, "old child still alive while the peer trickles"
            assert gone < 8, f"old child needed {gone:.1f}s to exit"
            assert server.small_ok(5), "new generation does not answer"
        finally:
            sock.close()
