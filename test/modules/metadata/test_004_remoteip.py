import os
import re

import pytest

from pyhttpd.depends import needs_dependency

from pyhttpd.conf import HttpdConf
from .env import MetadataTestEnv


@needs_dependency("mod_remoteip", MetadataTestEnv.has_shared_module("remoteip"),
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
            assert f.read().strip() == f"{self.CLIENT} {proxies}"

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
            assert f.read().strip() == f"{self.CLIENT} {proxies}"
