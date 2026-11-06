import os

import pytest

from pyhttpd.conf import HttpdConf
from .fcgi_faker import FcgiFaker

TARGET = b"fcgi-local-redirect-ok\n"


def cgi(*headers, body=b""):
    """A CGI response as a FastCGI application writes it to FCGI_STDOUT."""
    return b"".join(h.encode() + b"\r\n" for h in headers) + b"\r\n" + body


def echo(params, stdin):
    return cgi("Content-Type: text/plain", body=(
        f"method={params.get('REQUEST_METHOD')} "
        f"query={params.get('QUERY_STRING')}\n").encode())


class TestProxyFcgiLocalRedirect:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        if not env.has_shared_module("proxy_fcgi"):
            pytest.skip("mod_proxy_fcgi not available")
        docs = os.path.join(env.gen_dir, "apache", "htdocs", "test1")
        with open(os.path.join(docs, "fcgi-local-target"), "wb") as fd:
            fd.write(TARGET)
        faker = FcgiFaker("127.0.0.1", env.http_port2)
        faker.routes = {
            # RFC 3875 6.2.2, nothing but a local Location
            "/fcgi/local": cgi("Location: /fcgi-local-target"),
            "/fcgi/local-query": cgi("Location: /fcgi/echo?x=1"),
            "/fcgi/local-echo": cgi("Location: /fcgi/echo"),
            "/fcgi/echo": echo,
            # a client redirect
            "/fcgi/client": cgi("Location: https://example.invalid/target"),
            # a document response
            "/fcgi/doc": cgi("Content-Type: text/plain", body=b"normal-body"),
            # not the local redirect form: the response has a status
            "/fcgi/status": cgi("Status: 302 Found",
                                "Location: /fcgi-local-target"),
            # not the local redirect form: other headers and a body
            "/fcgi/doc-location": cgi("Content-Type: text/plain",
                                      "Location: /fcgi-local-target",
                                      body=b"normal-body"),
            "/fcgi/reuse-local": cgi("Location: /fcgi/reuse-echo"),
            "/fcgi/reuse-echo": echo,
        }
        faker.start()
        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port,
                         doc_root="htdocs/test1")
        conf.add([
            # the worker keeps its connections, which are not reused by default
            f"ProxyPass /fcgi/ fcgi://127.0.0.1:{env.http_port2}/"
            " disablereuse=off",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield faker
        faker.stop()

    def get(self, env, path, options=None):
        return env.curl_get(env.mkurl("http", "test1", path), options=options)

    # a local redirect is answered with the response for the local URL
    def test_proxy_007_01(self, env, _class_scope):
        r = self.get(env, "/fcgi/local")
        assert r.response["status"] == 200
        assert r.response["body"] == TARGET
        assert "location" not in r.response["header"]

    # the query string of the local URL is kept, the request is a GET
    def test_proxy_007_02(self, env, _class_scope):
        r = self.get(env, "/fcgi/local-query")
        assert r.response["status"] == 200
        assert r.response["body"] == b"method=GET query=x=1\n"

    # the body of the original request is not sent to the local URL again
    def test_proxy_007_03(self, env, _class_scope):
        _class_scope.reset()
        r = self.get(env, "/fcgi/local-echo", options=["--data", "abc=def"])
        assert r.response["status"] == 200
        assert r.response["body"] == b"method=GET query=\n"
        first, second = _class_scope.requests
        assert first["params"]["REQUEST_METHOD"] == "POST"
        assert first["stdin"] == b"abc=def"
        assert second["stdin"] == b""
        assert second["params"].get("CONTENT_LENGTH", "") in ("", "0")

    # HEAD stays HEAD
    def test_proxy_007_09(self, env, _class_scope):
        r = self.get(env, "/fcgi/local", options=["--head"])
        assert r.response["status"] == 200
        assert r.response["header"]["content-length"] == str(len(TARGET))

    # a connection which is kept is in a usable state after a local redirect
    def test_proxy_007_04(self, env, _class_scope):
        _class_scope.reset()
        for _ in range(3):
            r = self.get(env, "/fcgi/reuse-local")
            assert r.response["status"] == 200
            assert r.response["body"] == b"method=GET query=\n"
            r = self.get(env, "/fcgi/doc")
            assert r.response["status"] == 200
            assert r.response["body"] == b"normal-body"
        by_uri = {}
        for req in _class_scope.requests:
            by_uri.setdefault(req["uri"], []).append(req["conn"])
        # the redirected request ran right after the one which redirected,
        # in the same process, and used the connection it left behind
        assert by_uri["/fcgi/reuse-local"][0] == by_uri["/fcgi/reuse-echo"][0]

    # a document response is passed on as it was
    def test_proxy_007_05(self, env, _class_scope):
        r = self.get(env, "/fcgi/doc")
        assert r.response["status"] == 200
        assert r.response["body"] == b"normal-body"

    # a Location with a scheme is not local: it is not processed here, the
    # client gets it
    def test_proxy_007_06(self, env, _class_scope):
        r = self.get(env, "/fcgi/client")
        assert r.response["status"] in (200, 302)
        assert r.response["header"]["location"] == "https://example.invalid/target"
        assert r.response["body"] == b""

    # with a Status the response is not a local redirect
    def test_proxy_007_07(self, env, _class_scope):
        r = self.get(env, "/fcgi/status")
        assert r.response["status"] == 302
        assert r.response["header"]["location"] == "/fcgi-local-target"

    # with other headers and a body the response is not a local redirect
    def test_proxy_007_08(self, env, _class_scope):
        r = self.get(env, "/fcgi/doc-location")
        assert r.response["status"] == 200
        assert r.response["header"]["location"] == "/fcgi-local-target"
        assert r.response["body"] == b"normal-body"
