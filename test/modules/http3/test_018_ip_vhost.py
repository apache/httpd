import socket
import sys

import pytest

from .env import H3Conf, known_bug

# Two IP-based virtual hosts on one port, told apart only by the address the
# client connects to. All of 127.0.0.0/8 is local on Linux.
HOSTS = [("127.0.0.1", "test1"), ("127.0.0.2", "test2")]


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


def get(env, port, addr, h3):
    """GET /alive.json on port, connecting to addr."""
    url = f"https://{env.h3_domain}:{port}/alive.json"
    options = ["--connect-to", f"{env.h3_domain}:{port}:{addr}:{port}"]
    if h3:
        return env.h3_get(url, options=options)
    return env.curl_raw([url], options=["--http1.1"] + options)


@pytest.mark.skipif(sys.platform != "linux",
                    reason="needs a second loopback address")
class TestIpVhost:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        env.require_curl_http3()

    @staticmethod
    def install_ip_vhosts(env, port):
        conf = H3Conf(env)
        conf.add(f"Listen {port}")
        for addr, docs in HOSTS:
            conf.add([
                f"<VirtualHost {addr}:{port}>",
                f"ServerName {env.h3_domain}",
                f"DocumentRoot htdocs/{docs}",
                "SSLEngine on",
            ])
            for cred in env.get_credentials_for_name(env.h3_domain):
                conf.add_certificate(cred.cert_file, cred.pkey_file)
            conf.add_h3_protocol()
            conf.add("</VirtualHost>")
        conf.install()
        assert env.apache_restart() == 0
        assert env.wait_udp_port(port)

    # HTTP/3 selects the IP-based virtual host by the address the client
    # sent to, as TCP does
    def test_h3_018_01_by_address(self, env):
        port = free_port(env)
        self.install_ip_vhosts(env, port)
        for addr, docs in HOSTS:
            for h3 in [False, True]:
                r = get(env, port, addr, h3)
                proto = "HTTP/3" if h3 else "HTTP/1.1"
                assert r.exit_code == 0, f"{addr} {proto}: {r}"
                assert r.response["status"] == 200
                assert r.json["host"] == docs, \
                    f"{addr} over {proto} served by {r.json['host']}"

    # an address no IP-based virtual host names: TCP falls back to the main
    # server, which has no TLS here, so the HTTP/3 virtual host must not
    # serve it either (421, as test_h3_103_04 asks for a vhost whose TLS
    # setup differs from the HTTP/3 one)
    def test_h3_018_02_unmatched_address(self, env):
        port = free_port(env)
        self.install_ip_vhosts(env, port)
        r = get(env, port, "127.0.0.3", h3=True)
        known_bug(r.exit_code == 0 and r.response["status"] == 200
                  and r.json["host"] == "test1",
                  "an address no IP-based vhost names is served by the first "
                  "HTTP/3 vhost")
        # refused at the handshake, or 421 on the request
        assert r.exit_code != 0 or r.response["status"] == 421, f"{r}"
