import os
import re
import socket
import time

import pytest

from pyhttpd.conf import HttpdConf
from .env import MetadataTestEnv


@pytest.mark.skipif(condition=not MetadataTestEnv.has_shared_module("remoteip"),
                    reason="mod_remoteip not available")
class TestRemoteIp:
    LOG_FILE = "test_remoteip.log"
    PEER = "127.0.0.1"
    CLIENT = "203.0.113.7"
    CDN = "198.51.100.9"

    # The test requests come from the internal proxy PEER and carry
    # "X-Forwarded-For: CLIENT, CDN". The proxies are given directly or in
    # a list file, in the server config or in the vhost. Each case expects
    # the client and the (external) proxies seen by mod_remoteip.
    @pytest.mark.parametrize(["scope", "directives", "listed", "proxies"], [
        ["vhost", [f"RemoteIPInternalProxy {PEER}", f"RemoteIPTrustedProxy {CDN}"],
         [], CDN],
        ["vhost", [f"RemoteIPInternalProxy {PEER}", "RemoteIPTrustedProxyList {list}"],
         [CDN], CDN],
        ["vhost", ["RemoteIPTrustedProxyList {list}", f"RemoteIPInternalProxy {PEER}"],
         [CDN], CDN],
        ["vhost", ["RemoteIPTrustedProxy 10.142.1.99", "RemoteIPInternalProxyList {list}"],
         [PEER, CDN], "-"],
        ["server", [f"RemoteIPInternalProxy {PEER}", "RemoteIPTrustedProxyList {list}"],
         [CDN], CDN],
    ])
    def test_metadata_004_01(self, env, scope, directives, listed, proxies):
        list_file = os.path.join(env.gen_dir, "remoteip_proxies.lst")
        with open(list_file, "w") as f:
            f.write("".join(f"{ip}\n" for ip in listed))
        lines = [d.format(list=list_file) for d in directives]
        conf = HttpdConf(env, extras={
            "base": [
                "RemoteIPHeader X-Forwarded-For",
                f'CustomLog logs/{self.LOG_FILE} "%a %{{remoteip-proxy-ip-list}}n"',
            ] + (lines if scope == "server" else [])
        })
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], doc_root="htdocs/test1")
        if scope == "vhost":
            conf.add(lines)
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

        log_path = os.path.join(env.server_logs_dir, self.LOG_FILE)
        open(log_path, 'w').close()
        r = env.curl_get(env.mkurl("https", "test1", "/"), options=[
            '-H', f"X-Forwarded-For: {self.CLIENT}, {self.CDN}"])
        assert r.response["status"] == 200
        with open(log_path) as f:
            lines = [l.strip() for l in f if l.strip()
                     and not l.startswith(f"{self.PEER} -")]
            assert len(lines) == 1, f"expected 1 test line, got {lines}"
            assert lines[0] == f"{self.CLIENT} {proxies}"

    WARNING = r".*both the main server and the virtual host"

    # The proxy entries of the main server and of a vhost are merged, the
    # ones of the vhost taking precedence where subnets overlap, and a
    # warning tells when both have some.
    @pytest.mark.parametrize(["main", "vhost", "proxies", "warning"], [
        # only one of the scopes
        [[f"RemoteIPInternalProxy {PEER}", f"RemoteIPTrustedProxy {CDN}"],
         [], CDN, False],
        [[], [f"RemoteIPInternalProxy {PEER}", f"RemoteIPTrustedProxy {CDN}"],
         CDN, False],
        # RemoteIPInternalProxy in the main server, a list in the vhost
        [[f"RemoteIPInternalProxy {PEER}"], ["RemoteIPInternalProxyList {cdn}"],
         "-", True],
        [[f"RemoteIPInternalProxy {PEER}"], ["RemoteIPTrustedProxyList {cdn}"],
         CDN, True],
        # a list in the main server, a direct entry in the vhost
        [["RemoteIPInternalProxyList {peer}"], [f"RemoteIPTrustedProxy {CDN}"],
         CDN, True],
        # direct entries in both
        [[f"RemoteIPInternalProxy {PEER}"], [f"RemoteIPTrustedProxy {CDN}"],
         CDN, True],
        # the CDN is trusted by the main server and internal for the vhost
        [[f"RemoteIPInternalProxy {PEER}", f"RemoteIPTrustedProxy {CDN}"],
         [f"RemoteIPInternalProxy {CDN}"], "-", True],
        [[f"RemoteIPInternalProxy {PEER}", f"RemoteIPTrustedProxy {CDN}"],
         ["RemoteIPInternalProxyList {cdn}"], "-", True],
    ])
    def test_metadata_004_02(self, env, main, vhost, proxies, warning):
        files = {"cdn": self.CDN, "peer": self.PEER}
        for name, ip in files.items():
            with open(os.path.join(env.gen_dir, f"remoteip_{name}.lst"), "w") as f:
                f.write(f"{ip}\n")
        paths = {n: os.path.join(env.gen_dir, f"remoteip_{n}.lst") for n in files}
        conf = HttpdConf(env, extras={
            "base": [
                "RemoteIPHeader X-Forwarded-For",
                f'CustomLog logs/{self.LOG_FILE} "%a %{{remoteip-proxy-ip-list}}n"',
            ] + [d.format(**paths) for d in main]
        })
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], doc_root="htdocs/test1")
        conf.add([d.format(**paths) for d in vhost])
        conf.end_vhost()
        conf.install()
        pos = env.httpd_error_log.current_pos()
        assert env.apache_restart() == 0
        warned = env.httpd_error_log.wait_for(re.compile(self.WARNING), pos, timeout=1)
        assert warned == warning
        if warned:
            env.httpd_error_log.ignore_recent(matches=[self.WARNING])

        log_path = os.path.join(env.server_logs_dir, self.LOG_FILE)
        open(log_path, 'w').close()
        r = env.curl_get(env.mkurl("https", "test1", "/"), options=[
            '-H', f"X-Forwarded-For: {self.CLIENT}, {self.CDN}"])
        assert r.response["status"] == 200
        with open(log_path) as f:
            lines = [l.strip() for l in f if l.strip()
                     and not l.startswith(f"{self.PEER} -")]
            assert len(lines) == 1, f"expected 1 test line, got {lines}"
            assert lines[0] == f"{self.CLIENT} {proxies}"

    # -- PROXY protocol --------------------------------------------------

    # A v2 header: the signature, then version/command, family/transport,
    # the length of what follows, and the addresses.  The commands are LOCAL
    # (0) and PROXY (1); a health checker such as an AWS NLB sends LOCAL,
    # for which the receiver must keep the connection's own address and
    # ignore any address information present (bug 63893).
    PP2_SIG = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
    PP2_LOCAL = 0x20
    PP2_PROXY = 0x21
    PP2_UNSPEC = 0x00
    PP2_TCP4 = 0x11
    # CLIENT:4321 -> CDN:80, as a PROXY protocol TCPv4 address block
    PP2_ADDRS = (socket.inet_aton(CLIENT) + socket.inet_aton(CDN)
                 + (4321).to_bytes(2, "big") + (80).to_bytes(2, "big"))

    @classmethod
    def pp2_header(cls, cmd, fam=0x00, addrs=b""):
        return cls.PP2_SIG + bytes([cmd, fam]) + len(addrs).to_bytes(2, "big") + addrs

    def pp_install(self, env):
        """PROXY protocol on its own port, so the harness's own requests
        on the usual ports are unaffected; log the client address seen."""
        conf = HttpdConf(env, extras={
            "base": [
                f"Listen {env.http_port2}",
            ]
        })
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port2,
                         doc_root="htdocs/test1")
        conf.add(["RemoteIPProxyProtocol On",
                  f'CustomLog logs/{self.LOG_FILE} "%a"'])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    def pp_request(self, env, header, request=True):
        """Send a PROXY protocol header, then a request unless told not to;
        return (status, client address logged) - None for each if nothing
        came back."""
        log_path = os.path.join(env.server_logs_dir, self.LOG_FILE)
        open(log_path, 'w').close()
        sock = socket.create_connection(("127.0.0.1", env.http_port2), timeout=5)
        sock.sendall(header)
        if request:
            sock.sendall(f"GET / HTTP/1.1\r\nHost: test1.{env.http_tld}\r\n"
                         f"Connection: close\r\n\r\n".encode())
        data = b""
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, ConnectionError):
            pass
        sock.close()
        status = int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else None
        logged = None
        for _ in range(20):
            with open(log_path) as f:
                logged = f.read().strip() or None
            if logged or status is None:
                break
            time.sleep(0.1)
        return status, logged

    # Control: a PROXY command is honoured, the client is the one it names.
    def test_metadata_004_03(self, env):
        self.pp_install(env)
        hdr = self.pp2_header(self.PP2_PROXY, self.PP2_TCP4, self.PP2_ADDRS)
        assert self.pp_request(env, hdr) == (200, self.CLIENT)

    # A LOCAL command (ver_cmd 0x20) is valid: the request is served as
    # coming from the connection's own address, and nothing is logged as
    # an error.  Bug 63893.
    def test_metadata_004_04(self, env):
        self.pp_install(env)
        hdr = self.pp2_header(self.PP2_LOCAL, self.PP2_UNSPEC)
        assert self.pp_request(env, hdr) == (200, self.PEER)

    # LOCAL with an address block present: it must be ignored.
    def test_metadata_004_05(self, env):
        self.pp_install(env)
        hdr = self.pp2_header(self.PP2_LOCAL, self.PP2_TCP4, self.PP2_ADDRS)
        assert self.pp_request(env, hdr) == (200, self.PEER)

    # A health check which connects, sends an incomplete header and goes
    # away is not an error worth logging (bug 63893 comment 12).
    def test_metadata_004_06(self, env):
        self.pp_install(env)
        pos = env.httpd_error_log.current_pos()
        assert self.pp_request(env, self.PP2_SIG, request=False) == (None, None)
        logged = env.httpd_error_log.wait_for(re.compile(r".*AH10184"), pos,
                                              timeout=1)
        assert not logged, "peer going away mid-header was logged as an error"
