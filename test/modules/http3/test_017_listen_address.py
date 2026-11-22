import re
import socket
import sys
import time

import pytest

from .env import H3Conf

# All of 127.0.0.0/8 is local on Linux, so a second loopback address shows
# whether HTTP/3 answers on an address httpd was not told to listen on.
OTHER_ADDR = "127.0.0.2"
NOT_STARTED = r'.*HTTP/3 is not started'


def free_port(env) -> int:
    """A port free for UDP and for TCP on 127.0.0.1."""
    for _ in range(20):
        port = env.free_udp_port()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            s.close()
    pytest.fail("no free port for TCP and UDP")


def has_ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


def h3_vhost_on(env, port, listen, directives=None):
    """The HTTP/3 host on its own port, with the given Listen lines."""
    conf = H3Conf(env)
    conf.add(listen)
    conf.start_vhost(domains=[env.h3_domain], port=port,
                     doc_root="htdocs/test1", with_ssl=True)
    conf.add_h3_protocol()
    conf.add(directives or [])
    conf.end_vhost()
    conf.install()


def get(env, port, addr, h3=True):
    """GET /alive.json from the HTTP/3 host on port, connecting to addr."""
    url = f"https://{env.h3_domain}:{port}/alive.json"
    target = f"[{addr}]" if ":" in addr else addr
    options = ["--connect-to", f"{env.h3_domain}:{port}:{target}:{port}",
               "--connect-timeout", "3"]
    if h3:
        return env.h3_get(url, options=options)
    return env.curl_raw([url], options=["--http1.1"] + options)


def udp_bindable(addr, port) -> bool:
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    try:
        s.bind((addr, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


@pytest.mark.skipif(sys.platform != "linux",
                    reason="needs a second loopback address")
class TestListenAddress:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        env.require_curl_http3()

    # Listen with an address: HTTP/3 is served on that address only, like TCP
    def test_h3_017_01_single_address(self, env):
        port = free_port(env)
        h3_vhost_on(env, port, [f"Listen 127.0.0.1:{port}"])
        assert env.apache_restart() == 0
        assert env.wait_udp_port(port)
        r = get(env, port, "127.0.0.1")
        assert r.exit_code == 0, f"{r}"
        assert r.response["protocol"] == "HTTP/3"
        assert r.response["status"] == 200
        # TCP is not served on the other address, so neither is HTTP/3
        assert get(env, port, OTHER_ADDR, h3=False).exit_code != 0
        r = get(env, port, OTHER_ADDR)
        assert r.exit_code != 0, f"HTTP/3 answered on {OTHER_ADDR}: {r}"
        # the QUIC socket holds 127.0.0.1 alone, not the whole port
        assert udp_bindable(OTHER_ADDR, port)

    # Listen with no address: HTTP/3 is served on every address, as before
    def test_h3_017_02_wildcard(self, env):
        port = free_port(env)
        h3_vhost_on(env, port, [f"Listen {port}"])
        assert env.apache_restart() == 0
        assert env.wait_udp_port(port)
        for addr in ["127.0.0.1", OTHER_ADDR]:
            r = get(env, port, addr)
            assert r.exit_code == 0, f"{addr}: {r}"
            assert r.response["status"] == 200

    # Several addresses cannot share the one QUIC socket: HTTP/3 stays off
    # rather than answer on every address, and TCP is served as configured
    def test_h3_017_03_several_addresses(self, env):
        port = free_port(env)
        h3_vhost_on(env, port, [f"Listen 127.0.0.1:{port}",
                                f"Listen {OTHER_ADDR}:{port}"])
        assert env.apache_restart() == 0
        assert env.httpd_error_log.scan_recent(re.compile(NOT_STARTED),
                                               timeout=5)
        env.httpd_error_log.ignore_recent(matches=[NOT_STARTED])
        assert not env.udp_port_in_use(port)
        for addr in ["127.0.0.1", OTHER_ADDR]:
            r = get(env, port, addr, h3=False)
            assert r.exit_code == 0, f"{addr}: {r}"
            assert r.response["status"] == 200
            assert "alt-svc" not in r.response["header"], f"{r.response}"

    # a graceful restart to another Listen address binds the QUIC socket
    # again, rather than keep serving the old address
    def test_h3_017_04_graceful_new_address(self, env):
        port = free_port(env)
        h3_vhost_on(env, port, [f"Listen 127.0.0.1:{port}"])
        assert env.apache_restart() == 0
        assert get(env, port, "127.0.0.1").exit_code == 0
        env.rewrite_test_conf(f"Listen 127.0.0.1:{port}",
                              f"Listen {OTHER_ADDR}:{port}")
        assert env.apache_reload() == 0
        # the old generation may drain for a moment, so allow some time
        r = None
        for _ in range(50):
            r = get(env, port, OTHER_ADDR)
            if r.exit_code == 0:
                break
            time.sleep(0.2)
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        for _ in range(50):
            r = get(env, port, "127.0.0.1")
            if r.exit_code != 0:
                break
            time.sleep(0.2)
        assert r.exit_code != 0, f"HTTP/3 still answered on 127.0.0.1: {r}"

    # an H3Port of its own keeps the address of the host's TCP Listen
    def test_h3_017_05_own_h3_port(self, env):
        port = free_port(env)
        h3_port = free_port(env)
        h3_vhost_on(env, port, [f"Listen 127.0.0.1:{port}"],
                    directives=[f"H3Port {h3_port}"])
        assert env.apache_restart() == 0
        assert env.wait_udp_port(h3_port)
        r = get(env, h3_port, "127.0.0.1")
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        r = get(env, h3_port, OTHER_ADDR)
        assert r.exit_code != 0, f"HTTP/3 answered on {OTHER_ADDR}: {r}"
        assert udp_bindable(OTHER_ADDR, h3_port)

    # an IPv6 address is served alone, not as a dual-stack socket
    @pytest.mark.skipif(not has_ipv6_loopback(), reason="no ::1")
    def test_h3_017_06_ipv6_address(self, env):
        port = free_port(env)
        h3_vhost_on(env, port, [f"Listen [::1]:{port}"])
        assert env.apache_restart() == 0
        r = get(env, port, "::1")
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        r = get(env, port, "127.0.0.1")
        assert r.exit_code != 0, f"HTTP/3 answered on 127.0.0.1: {r}"
        assert udp_bindable("127.0.0.1", port)

    # a host with no port of its own is served by every listener, here the
    # wildcard ones of the test setup and one address: HTTP/3 stays off
    # rather than bind the wildcard
    def test_h3_017_07_host_without_port(self, env):
        port = free_port(env)
        conf = H3Conf(env)
        conf.add(f"Listen 127.0.0.3:{port}")
        conf.add([
            "<VirtualHost 127.0.0.3:*>",
            f"ServerName {env.h3_domain}",
            "DocumentRoot htdocs/test1",
            "SSLEngine on",
        ])
        for cred in env.get_credentials_for_name(env.h3_domain):
            conf.add_certificate(cred.cert_file, cred.pkey_file)
        conf.add_h3_protocol()
        conf.add([f"H3Port {port}", "</VirtualHost>"])
        conf.install()
        assert env.apache_restart() == 0
        assert env.httpd_error_log.scan_recent(re.compile(NOT_STARTED),
                                               timeout=5)
        env.httpd_error_log.ignore_recent(matches=[NOT_STARTED])
        assert not env.udp_port_in_use(port)
