import re

import pytest

from pyhttpd.conf import HttpdConf
from .env import TCPFaker


class _ResponseFaker(TCPFaker):

    def _make_response(self, data):
        first_line = data.split(b"\r\n")[0].decode("latin-1")
        path = first_line.split(" ")[1] if " " in first_line else "/"

        if "/content-type" in path:
            return """HTTP/1.1 200 OK\r\nContent-Type: 
            text/html\x00extra\r\n\r\n""".encode()

        if "/forwarded" in path:
            headers = data.split(b"\r\n\r\n")[0].decode("latin-1")
            forwarded = []
            for line in headers.split("\r\n"):
                if line.lower().startswith("x-forwarded-"):
                    forwarded.append(line)
            return ("HTTP/1.1 200 OK\r\n" + "\r\n".join(
                forwarded) + "\r\n\r\n").encode()

        if "/balancer" in path:
            headers = data.split(b"\r\n\r\n")[0].decode("latin-1")
            body_lines = []
            for line in headers.split("\r\n"):
                if ": " in line:
                    name, value = line.split(": ", 1)
                    body_lines.append(f"{name.upper()} = {value}")
            body = "\r\n".join(body_lines)
            return (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    f"Content-Length: {len(body.encode())}\r\n"
                    "\r\n"
                    + body
            ).encode()

        return super()._make_response(data)


class TestProxyResponse:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        faker = _ResponseFaker("127.0.0.1", env.http_port2)
        faker.start()

        conf = HttpdConf(env)
        conf.add([
            '<Proxy "balancer://xqacluster">',
            f'    BalancerMember "http://127.0.0.1:{env.http_port2 + 1}"',
            f'    BalancerMember "http://127.0.0.1:{env.http_port2}"',
            '    ProxySet forcerecovery=Off',
            '</Proxy>',
        ])
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port,
                         doc_root="htdocs", with_ssl=False)
        conf.add([
            "ProxyPass /balancer balancer://xqacluster/balancer",
            f"ProxyPass / http://127.0.0.1:{env.http_port2}/",
            f"ProxyPassReverse / http://127.0.0.1:{env.http_port2}/",
        ])
        if env.has_shared_module("remoteip"):
            conf.add([
                "RemoteIPHeader X-Forwarded-For",
                "RemoteIPTrustedProxy 0.0.0.0",
            ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield
        faker.stop()

    # check Content-Type
    def test_proxy_03_001(self, env):
        if not env.httpd_is_at_least("2.4.55"):
            pytest.skip(f'need at least httpd 2.4.55 for this')

        r = env.curl_get(env.mkurl("http", "test1", "/content-type"))
        assert r.response["status"] == 502

        env.httpd_error_log.ignore_recent(
            lognos=["AH01106", "AH10404"]
        )

    # checks X-Forwarded headers
    def test_proxy_03_002(self, env):
        if not env.httpd_is_at_least("2.4.54"):
            pytest.skip(f'need at least httpd 2.4.54 for this')

        r = env.curl_get(env.mkurl("http", "test1", "/forwarded"), options=[
            '-H', 'Connection: close, X-Forwarded-For, X-Forwarded-Host, '
                  'X-Forwarded-Server',
        ])
        assert r.response["status"] == 200
        assert "x-forwarded-for" in r.response["header"]
        assert "x-forwarded-host" in r.response["header"]
        assert "x-forwarded-server" in r.response["header"]

    # check body is preserved after failover
    def test_proxy_03_003(self, env):
        if not env.httpd_is_at_least("2.4.42"):
            pytest.skip(f'need at least httpd 2.4.42 for this')

        post_body = "123testing"
        r = env.curl_get(
            env.mkurl("http", "test1", "/balancer"),
            options=['--data', post_body, '-H', 'Content-Type: text/plain; '
                                                'charset=utf-8']
        )
        assert r.response["status"] == 200
        body = r.response["body"].decode("latin-1")
        m = re.search(r'CONTENT-LENGTH = (\d+)', body, re.IGNORECASE)
        assert m is not None
        assert int(m.group(1)) == len(post_body)
        env.httpd_error_log.ignore_recent(
            lognos=["AH00957", "AH00959", "AH01114"]
        )
