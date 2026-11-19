import pytest
import re
import socket
import threading

from .env import H2Conf, H2TestEnv


class DropFirstRelay:
    """TCP relay to an h2c backend that closes its first connection once
    the request HEADERS frame arrives, so mod_proxy_http2 has to retry."""

    PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    def __init__(self, backend_port):
        self._backend_port = backend_port
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self.accepted = 0

    def start(self):
        threading.Thread(target=self._serve, daemon=True).start()

    def stop(self):
        self._sock.close()

    def _serve(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.accepted += 1
            target = self._drop if self.accepted == 1 else self._relay
            threading.Thread(target=target, args=(conn,), daemon=True).start()

    def _drop(self, conn):
        buf = b""
        with conn:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                buf += data
                pos = len(self.PREFACE)
                while len(buf) >= pos + 9:
                    flen = int.from_bytes(buf[pos:pos + 3], "big")
                    if buf[pos + 3] == 0x1:  # HEADERS
                        return
                    pos += 9 + flen

    def _relay(self, conn):
        backend = socket.create_connection(("127.0.0.1", self._backend_port))

        def pipe(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        threading.Thread(target=pipe, args=(backend, conn), daemon=True).start()
        pipe(conn, backend)


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported(), reason="mod_http2 not supported here")
class TestH2Proxy:

    def test_h2_600_01(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "SetEnvIf Host (.+) X_HOST=$1",
            ]
        })
        conf.add_vhost_cgi(h2proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2proxy/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["json"]["protocol"] == "HTTP/2.0"
        assert r.response["json"]["https"] == "on"
        assert r.response["json"]["ssl_protocol"] != ""
        assert r.response["json"]["h2"] == "on"
        assert r.response["json"]["h2push"] == "off"
        assert r.response["json"]["host"] == f"cgi.{env.http_tld}:{env.https_port}"

    def test_h2_600_02(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "SetEnvIf Host (.+) X_HOST=$1",
                f"ProxyPreserveHost on",
                f"ProxyPass /h2c/ h2c://127.0.0.1:{env.http_port}/",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2c/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["json"]["protocol"] == "HTTP/2.0"
        assert r.response["json"]["https"] == ""
        # the proxied backend sees Host header as passed on front
        assert r.response["json"]["host"] == f"cgi.{env.http_tld}:{env.https_port}"
        assert r.response["json"]["h2_original_host"] == ""

    def test_h2_600_03(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "SetEnvIf Host (.+) X_HOST=$1",
                f"ProxyPreserveHost off",
                f"ProxyPass /h2c/ h2c://127.0.0.1:{env.http_port}/",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2c/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["json"]["protocol"] == "HTTP/2.0"
        assert r.response["json"]["https"] == ""
        # the proxied backend sees Host as using in connecting to it
        assert r.response["json"]["host"] == f"127.0.0.1:{env.http_port}"
        assert r.response["json"]["h2_original_host"] == ""

    # check that connection reuse actually happens as configured
    @pytest.mark.parametrize("enable_reuse", [ "on", "off" ])
    def test_h2_600_04(self, env, enable_reuse):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                f"ProxyPassMatch ^/h2proxy/([0-9]+)/(.*)$ "
                f"  h2c://127.0.0.1:$1/$2 enablereuse={enable_reuse} keepalive=on",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", f"/h2proxy/{env.http_port}/hello.py")
        # httpd 2.5.0 disables reuse, not matter the config
        if enable_reuse == "on" and not env.httpd_is_at_least("2.4.60"):
            # reuse is not guaranteed for each request, but we expect some
            # to do it and run on a h2 stream id > 1
            reused = False
            count = 10
            r = env.curl_raw([url] * count, 5)
            response = r.response
            for n in range(count):
                assert response["status"] == 200
                if n == (count - 1):
                    break
                response = response["previous"]
            assert r.json[0]["h2_stream_id"] == "1"
            for n in range(1, count):
                if int(r.json[n]["h2_stream_id"]) > 1:
                    reused = True
                    break
            assert reused
        else:
            r = env.curl_raw([url, url], 5)
            assert r.response["previous"]["status"] == 200
            assert r.response["status"] == 200
            assert r.json[0]["h2_stream_id"] == "1"
            assert r.json[1]["h2_stream_id"] == "1"

    # do some flexible setup from #235 to proper connection selection
    @pytest.mark.parametrize("enable_reuse", [ "on", "off" ])
    def test_h2_600_05(self, env, enable_reuse):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                f"ProxyPassMatch ^/h2proxy/([0-9]+)/(.*)$ "
                f"  h2c://127.0.0.1:$1/$2 enablereuse={enable_reuse} keepalive=on",
            ]
        })
        conf.add_vhost_cgi()
        conf.add([
            f'Listen {env.http_port2}',
            'UseCanonicalName On',
            'UseCanonicalPhysicalPort On'
        ])
        conf.start_vhost(domains=[f'cgi.{env.http_tld}'],
                         port=env.http_port2, doc_root="htdocs/cgi")
        conf.add("AddHandler cgi-script .py")
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", f"/h2proxy/{env.http_port}/hello.py")
        url2 = env.mkurl("https", "cgi", f"/h2proxy/{env.http_port2}/hello.py")
        r = env.curl_raw([url, url2], 5)
        assert r.response["previous"]["status"] == 200
        assert int(r.json[0]["port"]) == env.http_port
        assert r.response["status"] == 200
        exp_port = env.http_port if enable_reuse == "on" \
                                    and not env.httpd_is_at_least("2.4.60")\
            else env.http_port2
        assert int(r.json[1]["port"]) == exp_port

    # test X-Forwarded-* headers
    def test_h2_600_06(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "SetEnvIf Host (.+) X_HOST=$1",
                f"ProxyPreserveHost on",
                f"ProxyPass /h2c/ h2c://127.0.0.1:{env.http_port}/",
                f"ProxyPass /h1c/ http://127.0.0.1:{env.http_port}/",
            ]
        })
        conf.add_vhost_cgi(proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h1c/hello.py")
        r1 = env.curl_get(url, 5)
        assert r1.response["status"] == 200
        url = env.mkurl("https", "cgi", "/h2c/hello.py")
        r2 = env.curl_get(url, 5)
        assert r2.response["status"] == 200
        for key in ['x-forwarded-for', 'x-forwarded-host','x-forwarded-server']:
            assert r1.json[key] == r2.json[key], f'{key} differs proxy_http != proxy_http2'

    # a request retried on a new backend connection must keep the Host
    # the client sent, port included (PR 67086)
    def test_h2_600_07(self, env):
        relay = DropFirstRelay(env.http_port)
        relay.start()
        try:
            conf = H2Conf(env, extras={
                f'cgi.{env.http_tld}': [
                    "SetEnvIf Host (.+) X_HOST=$1",
                    "ProxyPreserveHost on",
                    f"ProxyPass /h2c/ h2c://127.0.0.1:{relay.port}/",
                ]
            })
            conf.add_vhost_cgi()
            conf.install()
            assert env.apache_restart() == 0
            url = env.mkurl("https", "cgi", "/h2c/hello.py")
            r = env.curl_get(url, 5)
            assert relay.accepted == 2, f'{r}'
            assert r.response["status"] == 200
            front = f"cgi.{env.http_tld}:{env.https_port}"
            assert r.response["json"]["host"] == front
            assert r.response["json"]["x-forwarded-host"] == front
        finally:
            relay.stop()

    # the Host header of the request stays visible after proxying
    def test_h2_600_08(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "ProxyPreserveHost on",
                f"ProxyPass /h2c/ h2c://127.0.0.1:{env.http_port}/",
                'Header set X-Front-Host "expr=%{req:Host}"',
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2c/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["header"]["x-front-host"] == \
            f"cgi.{env.http_tld}:{env.https_port}"

    # a request without Host gets no Host invented after proxying
    def test_h2_600_09(self, env):
        conf = H2Conf(env, extras={
            'base': [
                'ProxyPreserveHost on',
                f'ProxyPass /test/ h2c://127.0.0.1:{env.http_port}/',
                '<Location /test/>',
                '  Header always set X-Front-Host "expr=%{req:Host}"',
                '</Location>',
            ],
        })
        conf.install()
        assert env.apache_restart() == 0
        with socket.create_connection(
                ('localhost', int(env.http_port)), timeout=5) as sock:
            sock.sendall(b"GET /test/ HTTP/1.0\r\n\r\n")
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        assert env.httpd_error_log.scan_recent(
            re.compile(r'.*AH10511: incoming HTTP/0\.9 request'), timeout=5)
        env.httpd_error_log.ignore_recent(matches=[
            r'.*HTTP/0\.9 request \(with no Host header\).*', ],
            lognos=["AH10511"])
        head = data.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
        assert head[0].startswith("HTTP/1.1 "), f'{data!r}'
        headers = {}
        for line in head[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        assert headers.get("x-front-host") == "", f'{head}'

    # lets do some error tests
    def test_h2_600_30(self, env):
        conf = H2Conf(env)
        conf.add_vhost_cgi(h2proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/error?status=500")
        r = env.curl_get(url)
        assert r.exit_code == 0, r
        assert r.response['status'] == 500
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/error?error=timeout")
        r = env.curl_get(url)
        assert r.exit_code == 0, r
        assert r.response['status'] == 408

    # produce an error during response body
    def test_h2_600_31(self, env, repeat):
        conf = H2Conf(env)
        conf.add_vhost_cgi(h2proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/error?body_error=timeout")
        r = env.curl_get(url)
        # depending on when the error is detect in proxying, if may RST the
        # stream (exit_code != 0) or give a 503 response.
        if r.exit_code == 0:
            assert r.response['status'] == 502

    # produce an error, fail to generate an error bucket
    def test_h2_600_32(self, env, repeat):
        conf = H2Conf(env)
        conf.add_vhost_cgi(h2proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/error?body_error=timeout&error_bucket=0")
        r = env.curl_get(url)
        # depending on when the error is detect in proxying, if may RST the
        # stream (exit_code != 0) or give a 503 response.
        if r.exit_code == 0:
            assert r.response['status'] in [502, 503]

    # test missing host header
    def test_h2_600_33(self, env):

        conf = H2Conf(env, extras={
            'base': [
                'ProxyPreserveHost on',
                f'ProxyPass /test/ h2c://127.0.0.1:{env.http_port}/',
            ],
        })
        conf.install()
        assert env.apache_restart() == 0

        with socket.create_connection(
                ('localhost', int(env.http_port))) as sock:
            sock.sendall("GET /test/\r\n\r\n".encode())
        warn_message = re.compile(
            r'.*HTTP/0\.9 request \(with no Host header\)'
            r' and preserve host set, forcing hostname.*'
        )
        assert env.httpd_error_log.scan_recent(warn_message, timeout=5)
        env.httpd_error_log.ignore_recent(matches=[
            r'.*HTTP/0\.9 request \(with no Host header\).*', ],
            lognos=["AH10511"])
