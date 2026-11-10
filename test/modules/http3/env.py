import inspect
import logging
import os
import re
import socket
import subprocess
import time
from typing import Dict, Any, List, Optional

import pytest

from pyhttpd.certs import CertificateSpec
from pyhttpd.conf import HttpdConf
from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)

DATA_SIZES = {"h3data-0": 0, "h3data-1k": 1024, "h3data-100k": 100 * 1024,
              "h3data-1m": 1024 * 1024, "h3data-10m": 10 * 1024 * 1024}


def known_bug(failed: bool, reason: str):
    # an xfail mark would also turn the error log check at teardown into
    # an xfail, hiding whatever else the test made httpd log
    if failed:
        pytest.xfail(reason)


def data_bytes(size: int) -> bytes:
    """Content that shows where a misplaced chunk came from."""
    line = b"0123456789abcdef" * 4
    out = bytearray()
    while len(out) < size:
        out += b"%08d:" % len(out) + line + b"\n"
    return bytes(out[:size])


class H3TestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(H3TestSetup)))
        self.add_modules(["http3", "ssl", "unique_id", "remoteip", "include",
                          "setenvif", "headers"])
        self.add_cgi_module()

    def make(self):
        super().make()
        docs = os.path.join(self.env.server_docs_dir, "test1")
        for name, size in DATA_SIZES.items():
            with open(os.path.join(docs, name), "wb") as fd:
                fd.write(data_bytes(size))


class H3TestEnv(HttpdTestEnv):

    def curl_has_http3(self) -> bool:
        """Whether the curl in use can speak HTTP/3."""
        try:
            p = subprocess.run([self.curl, "-V"],
                               capture_output=True, text=True)
        except OSError:
            return False
        m = re.search(r'^Features:(.*)$', p.stdout, re.MULTILINE)
        return m is not None and "HTTP3" in m.group(1).split()

    def require_curl_http3(self):
        self.require(self.curl_has_http3(), "curl lacks HTTP/3 support",
                     dep="curl HTTP3", detected=self.curl_version_str())

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["http3"])
        self.add_cert_specs([CertificateSpec(domains=[f"other.{self.http_tld}"])])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=H3TestSetup(env=self))

    @property
    def h3_port(self) -> int:
        # the QUIC listener shares the number of the TLS port, over UDP
        return self.https_port

    def h3_get(self, url: str, options: Optional[List[str]] = None):
        return self.curl_raw([url], options=["--http3-only"] + (options or []))

    def h3_client(self, **kwargs):
        """An aioquic client, for when curl is not enough."""
        self.require(self.has_python_package("aioquic"),
                     "python package 'aioquic' is not installed",
                     dep="aioquic")
        from .h3client import H3Client
        return H3Client(self, **kwargs)

    @property
    def h3_domain(self) -> str:
        return f"test1.{self.http_tld}"

    @property
    def other_domain(self) -> str:
        """Has its own certificate, which the HTTP/3 listener does not."""
        return f"other.{self.http_tld}"

    @staticmethod
    def udp_port_in_use(port: int) -> bool:
        """Whether something holds the UDP port, on IPv4 or IPv6."""
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.bind(("::", port))
            return False
        except OSError:
            return True
        finally:
            s.close()

    def wait_udp_port(self, port: int, in_use: bool = True,
                      timeout: float = 5) -> bool:
        end = time.monotonic() + timeout
        while True:
            if self.udp_port_in_use(port) == in_use:
                return True
            if time.monotonic() >= end:
                return False
            time.sleep(0.1)

    @staticmethod
    def free_udp_port() -> int:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.bind(("::", 0))
            return s.getsockname()[1]
        finally:
            s.close()

    @staticmethod
    def hold_udp_port(port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.bind(("::", port))
        return s

    def alt_svc(self, domain: str = None, port: int = None,
                scheme: str = "https"):
        """The Alt-Svc header of a TCP request to the vhost, or None."""
        if domain is None:
            domain = self.h3_domain
        if port is None:
            port = self.https_port if scheme == "https" else self.http_port
        r = self.curl_get(f"{scheme}://{domain}:{port}/")
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200, f"{r.response}"
        return r.response["header"].get("alt-svc")


class H3Conf(HttpdConf):
    """A configuration with HTTP/3 on the https port of the test1 vhost.

    mod_http3 serves HTTP/3 on a host that lists h3 in Protocols, with the
    certificate mod_ssl has for it, and opens one UDP listener for the
    first such virtual host defined. test1 carries the H3 directives and
    every other vhost on the https port is reached through the same QUIC
    connection by its Host header. The default certificate covers all test
    domains.
    """

    def __init__(self, env: H3TestEnv, extras: Dict[str, Any] = None):
        super().__init__(env=env, extras=extras)

    def add_h3_vhosts(self, test1: List[str] = None, test2: List[str] = None,
                      cgi: List[str] = None):
        self.start_vhost(domains=[f"test1.{self.env.http_tld}"],
                         port=self.env.https_port, doc_root="htdocs/test1")
        self.add([
            "Protocols h3 http/1.1",
            f"H3Port {self.env.h3_port}",
        ])
        self.add(test1 or [])
        self.end_vhost()
        self.start_vhost(domains=[f"test2.{self.env.http_tld}"],
                         port=self.env.https_port, doc_root="htdocs/test2")
        self.add(test2 or [])
        self.end_vhost()
        self.start_vhost(domains=[f"cgi.{self.env.http_tld}"],
                         port=self.env.https_port, doc_root="htdocs/cgi")
        self.add(["AddHandler cgi-script .py"])
        self.add(cgi or [])
        self.end_vhost()
        return self

    def add_h3_protocol(self):
        """HTTP/3 with the certificate mod_ssl has for the host."""
        self.add("Protocols h3 http/1.1")
        return self

    def add_h3_vhost(self, directives: List[str] = None, domain: str = None):
        """test1 alone on the https port, serving HTTP/3 and /cgi/."""
        if domain is None:
            domain = self.env.h3_domain
        self.start_vhost(domains=[domain], port=self.env.https_port,
                         doc_root="htdocs/test1")
        self.add(f'Alias /cgi/ "{self.env.server_docs_dir}/cgi/"')
        self.add_h3_protocol()
        if directives:
            self.add(directives)
        self.end_vhost()
        return self
