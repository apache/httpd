r"""mpm_motorz: a child told to stop gracefully finishes the connections it has.

The server delivers a large static file.  The client reads a little of it and
stops, so that the server fills the socket buffers and the connection is parked
in the MPM waiting to write.  Then the parent is sent the graceful restart
signal.  The old child must keep serving that connection until the whole body
has been delivered, while the new generation answers other requests.

The body has to come from the core handler: a handler that writes it itself
(mod_test_rwrite) blocks a worker thread for the whole transfer, and the
connection is then never parked, so the test passes even without the drain.

The test runs a private httpd: restarting the suite's own server would change
its state (its worker set, the log, ...) for the tests that run after this one.
"""

import os
import re
import signal
import socket
import subprocess
import sys
import time

import pytest

BODY_LENGTH = 64 * 1024 * 1024
SMALL_LENGTH = 1000

# What the private server needs, taken from the suite's generated config so that
# paths and module names are the ones this build uses.
WANTED_MODULES = ("mpm_", "unixd_module", "authz_core_module")


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def load_module_lines(config):
    text = open(config.vars["t_conf_file"], encoding="utf-8").read()
    lines = []
    for m in re.finditer(r"^\s*(LoadModule\s+(\S+)\s+.*)$", text, re.M):
        if m.group(2).startswith(WANTED_MODULES[0]) or m.group(2) in WANTED_MODULES:
            lines.append(m.group(1).strip())
    return lines


def read_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    return head, body


def get(port, path, rcvbuf=None):
    """Send an HTTP/1.0 GET; return the open socket (the body ends at close)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if rcvbuf:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    sock.settimeout(30)
    sock.connect(("127.0.0.1", port))
    sock.sendall(f"GET {path} HTTP/1.0\r\n\r\n".encode())
    return sock


@pytest.mark.skipif(sys.platform == "win32", reason="signals")
def test_graceful_restart_does_not_cut_a_download(config, tmp_path):
    if config.info.mpm != "motorz":
        pytest.skip("motorz only")

    docroot = tmp_path / "htdocs"
    docroot.mkdir()
    (docroot / "big.bin").write_bytes(b"x" * BODY_LENGTH)
    (docroot / "small.txt").write_bytes(b"y" * SMALL_LENGTH)

    port = free_port()
    conf = tmp_path / "httpd.conf"
    conf.write_text(
        "\n".join(
            [
                f'ServerRoot "{tmp_path}"',
                "ServerName localhost",
                f"Listen 127.0.0.1:{port}",
                f'PidFile "{tmp_path}/httpd.pid"',
                f'ErrorLog "{tmp_path}/error_log"',
                "LogLevel info",
                *load_module_lines(config),
                "StartServers 1",
                "ThreadsPerChild 10",
                f'DocumentRoot "{docroot}"',
                "<IfModule mime_module>",
                "    TypesConfig /dev/null",
                "</IfModule>",
                "",
            ]
        )
    )
    httpd = [str(config.info.httpd), "-f", str(conf), "-DFOREGROUND"]
    check = subprocess.run([*httpd, "-t"], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr

    # Its own process group, so that the children go away with the parent.
    proc = subprocess.Popen(httpd, start_new_session=True)
    sock = None
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert proc.poll() is None, f"httpd exited, see {tmp_path}/error_log"
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.1)

        sock = get(port, "/big.bin", rcvbuf=4096)
        head, body = read_headers(sock)
        assert b" 200 " in head.split(b"\r\n")[0], head
        received = len(body)

        # Let the server run into the closed window, then restart gracefully.
        time.sleep(1)
        os.kill(proc.pid, signal.SIGUSR1)

        # The new generation answers other requests while the old child drains.
        other = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                s = get(port, "/small.txt")
                h, b = read_headers(s)
                while chunk := s.recv(4096):
                    b += chunk
                s.close()
                if b" 200 " in h.split(b"\r\n")[0]:
                    other = len(b)
                    break
            except OSError:
                pass
            time.sleep(0.2)
        assert other == SMALL_LENGTH, "no response after the graceful restart"

        # The old child has had time to exit if it had dropped the connection.
        time.sleep(1)
        while chunk := sock.recv(65536):
            received += len(chunk)
    finally:
        if sock:
            sock.close()
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except OSError:
            pass
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()

    assert received == BODY_LENGTH
