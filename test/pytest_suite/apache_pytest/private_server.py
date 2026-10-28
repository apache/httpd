"""A throwaway private httpd for tests that must restart or reconfigure the
server (the suite's own server is shared, so they cannot use it).

It serves one small and one large static file.  Module and path settings are
taken from the suite's generated config so that they match the build under test.
"""

import re
import socket
import subprocess
import time

from pyhttpd.instance import HttpdInstance, free_port  # noqa: F401  (free_port re-exported)

BODY_LENGTH = 64 * 1024 * 1024
SMALL_LENGTH = 1000

# What the private server needs, taken from the suite's generated config so that
# paths and module names are the ones this build uses.
WANTED_MODULES = ("mpm_", "unixd_module", "authz_core_module",
                  "unique_id_module", "headers_module", "echo_module")


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


def child_pids(parent):
    """Pids of the direct children of parent (portable: macOS and Linux)."""
    out = subprocess.run(["ps", "-A", "-o", "pid=,ppid="],
                         capture_output=True, text=True).stdout
    pids = set()
    for line in out.splitlines():
        fields = line.split()
        if len(fields) == 2 and int(fields[1]) == parent:
            pids.add(int(fields[0]))
    return pids


def get(port, path, rcvbuf=None):
    """Send an HTTP/1.0 GET; return the open socket (the body ends at close)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if rcvbuf:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    sock.settimeout(30)
    sock.connect(("127.0.0.1", port))
    sock.sendall(f"GET {path} HTTP/1.0\r\n\r\n".encode())
    return sock


class PrivateServer:
    """A throwaway httpd with one small and one large static file."""

    def __init__(self, config, tmp_path, extra=(), big_length=BODY_LENGTH):
        self.config = config
        self.tmp_path = tmp_path
        self.extra = list(extra)
        self.big_length = big_length
        self.port = free_port()
        self.instance = None

    def start(self):
        tmp_path = self.tmp_path
        docroot = tmp_path / "htdocs"
        docroot.mkdir()
        (docroot / "big.bin").write_bytes(b"x" * self.big_length)
        (docroot / "small.txt").write_bytes(b"y" * SMALL_LENGTH)

        conf = tmp_path / "httpd.conf"
        conf.write_text(
            "\n".join(
                [
                    f'ServerRoot "{tmp_path}"',
                    "ServerName localhost",
                    f"Listen 127.0.0.1:{self.port}",
                    f'PidFile "{tmp_path}/httpd.pid"',
                    f'ErrorLog "{tmp_path}/error_log"',
                    "LogLevel info",
                    *load_module_lines(self.config),
                    "StartServers 1",
                    "ThreadsPerChild 10",
                    f'DocumentRoot "{docroot}"',
                    "<IfModule mime_module>",
                    "    TypesConfig /dev/null",
                    "</IfModule>",
                    *self.extra,
                    "",
                ]
            )
        )
        # Its own process group, so that the children go away with the parent.
        self.instance = HttpdInstance(
            self.config.info.httpd, ["-f", str(conf)],
            ports=[self.port], error_log=tmp_path / "error_log",
            stderr_file=tmp_path / "stderr", configtest_first=True)
        self.instance.start(timeout=20)

    @property
    def proc(self):
        return self.instance.proc if self.instance else None

    def stop(self):
        if self.instance is not None:
            self.instance.stop(timeout=15)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def graceful(self, timeout=30):
        """Ask for a graceful restart and return once the parent has done it. A
        slow (instrumented) parent can take seconds to act on the signal, and a
        test that goes on before that is not restarting the server when it
        thinks it is."""
        self.instance.restart(graceful=True, timeout=timeout)

    def error_log(self):
        return (self.tmp_path / "error_log").read_text(errors="replace")

    def small_ok(self, timeout):
        """True if /small.txt is served completely within timeout seconds."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                s = get(self.port, "/small.txt")
                s.settimeout(1)
                h, b = read_headers(s)
                while chunk := s.recv(4096):
                    b += chunk
                s.close()
                if b" 200 " in h.split(b"\r\n")[0] and len(b) == SMALL_LENGTH:
                    return True
            except OSError:
                pass
            time.sleep(0.1)
        return False
