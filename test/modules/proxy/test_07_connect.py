import socket

import pytest

from pyhttpd.conf import HttpdConf


class TestProxyConnect:
    """AllowCONNECT, including the documented "None" value which disallows
    CONNECT to all ports (including the 443/563 defaults)."""

    def _mk_proxy(self, env, allow_connect):
        # A forward proxy on its own (plain HTTP) port, so a raw CONNECT can
        # be sent to it and the vhost handling it is unambiguous.
        conf = HttpdConf(env)
        conf.add(f"Listen {env.proxy_port}")
        conf.start_vhost(domains=[env.d_forward], port=env.proxy_port)
        conf.add([
            "ProxyRequests on",
            allow_connect,
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    def _connect_status(self, env, target):
        # Send a raw CONNECT request to the forward proxy and return the
        # numeric status of its response.
        req = f"CONNECT {target} HTTP/1.0\r\nHost: {target}\r\n\r\n"
        with socket.create_connection(("127.0.0.1", env.proxy_port),
                                      timeout=5) as s:
            s.sendall(req.encode())
            buf = b""
            while b"\r\n" not in buf:
                data = s.recv(1024)
                if not data:
                    break
                buf += data
        line = buf.split(b"\r\n", 1)[0].decode("latin-1")
        return int(line.split(" ", 2)[1])

    def test_proxy_connect_07_none(self, env):
        # AllowCONNECT None rejects every CONNECT with 403, including the
        # default https port and an otherwise-reachable target.
        self._mk_proxy(env, "AllowCONNECT None")
        assert self._connect_status(env, "127.0.0.1:443") == 403
        assert self._connect_status(env, f"127.0.0.1:{env.http_port}") == 403
        # the two rejections each log "Connect to remote machine blocked"
        env.httpd_error_log.ignore_recent(lognos=["AH00898"])

    def test_proxy_connect_07_allowed(self, env):
        # Control: with the port explicitly allowed, the same CONNECT tunnels
        # (200 Connection Established) - so it is None, above, which blocks it.
        self._mk_proxy(env, f"AllowCONNECT {env.http_port}")
        assert self._connect_status(env, f"127.0.0.1:{env.http_port}") == 200

    def test_proxy_connect_07_inherit_override(self, env):
        # "AllowCONNECT None" at the main-server level is overridden by an
        # explicit port list in the vhost: that port is allowed there (200),
        # while a port not listed remains blocked (403).
        conf = HttpdConf(env)
        conf.add("AllowCONNECT None")
        conf.add(f"Listen {env.proxy_port}")
        conf.start_vhost(domains=[env.d_forward], port=env.proxy_port)
        conf.add([
            "ProxyRequests on",
            f"AllowCONNECT {env.http_port}",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        assert self._connect_status(env, f"127.0.0.1:{env.http_port}") == 200
        assert self._connect_status(env, "127.0.0.1:443") == 403
        env.httpd_error_log.ignore_recent(lognos=["AH00898"])

    def test_proxy_connect_07_merge_union(self, env):
        # Two port lists (main-server and vhost) still merge as a union, so a
        # port allowed at the main-server level stays allowed in the vhost.
        conf = HttpdConf(env)
        conf.add(f"AllowCONNECT {env.http_port}")
        conf.add(f"Listen {env.proxy_port}")
        conf.start_vhost(domains=[env.d_forward], port=env.proxy_port)
        conf.add([
            "ProxyRequests on",
            "AllowCONNECT 563",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        assert self._connect_status(env, f"127.0.0.1:{env.http_port}") == 200
        assert self._connect_status(env, "127.0.0.1:9") == 403
        env.httpd_error_log.ignore_recent(lognos=["AH00898"])

    def test_proxy_connect_07_conflict(self, env):
        # "None" and a port number in the same context is a config error.
        conf = HttpdConf(env)
        conf.add(f"Listen {env.proxy_port}")
        conf.start_vhost(domains=[env.d_forward], port=env.proxy_port)
        conf.add([
            "ProxyRequests on",
            "AllowCONNECT None",
            "AllowCONNECT 443",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() != 0
        # leave a working server behind for teardown / any later test
        self._mk_proxy(env, "AllowCONNECT None")
