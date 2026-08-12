r"""Translated from t/modules/proxy.t -- mod_proxy reverse proxying.

Reverse-proxies through the proxy_http_reverse vhost (and proxy_http_nofwd /
proxy_http_balancer for some cases), checking proxied bodies, X-Forwarded-For
behaviour, query-string passthrough, abs_path decoding (PR 15207), ProxyPass
not-proxied content, redirect rewriting (with mod_alias / balancer), UDS, and
mapping=servlet path normalisation. CGI / lua / alias / balancer cases gate on
the relevant module being present.

Perl original: plan tests => 46, need need_module 'proxy', need_module 'setenvif'.
"""

import os
import re
import socket
import sys
import threading
import time

import pytest

from apache_pytest import need_module, t_cmp


def _have_cgi(http):
    return http.have_module("cgid") or http.have_module("cgi")


@need_module("proxy", "setenvif")
def test_proxy_reverse(http):
    http.module("proxy_http_reverse")
    try:
        r = http.GET("/reverse/")
        assert t_cmp(r.status_code, 200), "reverse proxy"
        assert t_cmp(r.text, re.compile(r"^welcome to ")), "reverse proxied body"

        r = http.GET("/reverse/index.html")
        assert t_cmp(r.status_code, 200), "reverse proxy to index.html"
        assert t_cmp(r.text, re.compile(r"^welcome to ")), "reverse proxied body index"

        if http.have_min_apache_version("2.4.49"):
            r = http.GET("/reverse-match/")
            assert t_cmp(r.status_code, 200), "reverse proxy match"
            assert t_cmp(r.text, re.compile(r"^welcome to "))
            r = http.GET("/reverse-match/index.html")
            assert t_cmp(r.status_code, 200), "reverse proxy match to index.html"
            assert t_cmp(r.text, re.compile(r"^welcome to "))

        for path in ("/reverse-slash", "/reverse-slash/", "/reverse-slash/index.html"):
            r = http.GET(path)
            assert t_cmp(r.status_code, 200), f"reverse proxy {path}"
            assert t_cmp(r.text, re.compile(r"^welcome to "))

        if http.have_min_apache_version("2.4.0"):
            r = http.GET("/reverse/locproxy/")
            assert t_cmp(r.status_code, 200), "reverse Location-proxy to index.html"
            assert t_cmp(r.text, re.compile(r"^welcome to "))

        if http.have_min_apache_version("2.4.26"):
            # trapped by SetEnvIf no-proxy => 404
            r = http.GET("/reverse/locproxy/index.html")
            assert t_cmp(r.status_code, 404), \
                "reverse Location-proxy blocked by no-proxy env"
    finally:
        http.module(None)


@need_module("proxy", "setenvif")
def test_proxy_cgi(http):
    if not _have_cgi(http):
        pytest.skip("no CGI module")
    http.module("proxy_http_reverse")
    try:
        r = http.GET("/reverse/modules/cgi/env.pl")
        assert t_cmp(r.status_code, 200), "reverse proxy to env.pl"
        assert t_cmp(r.text, re.compile(r"^APACHE_TEST_HOSTNAME = ")), \
            "reverse proxied env.pl response"
        assert t_cmp(r.text, re.compile(r"HTTP_X_FORWARDED_FOR = ")), \
            "X-Forwarded-For enabled"

        if http.have_min_apache_version("2.4.28"):
            http.module("proxy_http_nofwd")
            r = http.GET("/reverse/modules/cgi/env.pl")
            assert t_cmp(r.status_code, 200), "reverse proxy to env.pl without X-F-F"
            assert not t_cmp(r.text, re.compile(r"HTTP_X_FORWARDED_FOR = ")), \
                "reverse proxied env.pl w/o X-F-F"
            http.module("proxy_http_reverse")

        r = http.GET("/reverse/modules/cgi/env.pl?reverse-proxy")
        assert t_cmp(r.status_code, 200), "reverse proxy with query string"
        assert t_cmp(r.text, re.compile(r"QUERY_STRING = reverse-proxy\r?\n", re.S)), \
            "reverse proxied query string OK"

        r = http.GET("/reverse/modules/cgi/nph-dripfeed.pl")
        assert t_cmp(r.status_code, 200), "reverse proxy to dripfeed CGI"
        assert t_cmp(r.text, "abcdef"), "reverse proxied to dripfeed CGI content OK"

        if http.have_min_apache_version("2.1.0"):
            # nph-102.pl emits a 102 Processing interim response then a 200.
            # The Perl test asserted the LWP-surfaced code 102 (empty body) and
            # noted LWP needed fixing for 1xx. httpx correctly consumes the
            # interim and returns the final 200 ("this is nph-stdout"); accept
            # either the legacy 102/empty or the proper 200/body.
            r = http.GET("/reverse/modules/cgi/nph-102.pl")
            if r.status_code == 102:
                assert t_cmp(r.text, ""), "reverse proxy 102 response"
            else:
                assert t_cmp(r.status_code, 200), "reverse proxy to nph-102 (final)"
                assert t_cmp(r.text, "this is nph-stdout"), \
                    "reverse proxy 102->200 response body"
    finally:
        http.module(None)


@need_module("proxy", "setenvif")
def test_proxy_pr15207(http):
    if not http.have_min_apache_version("2.0.55"):
        pytest.skip("PR 15207 requires httpd >= 2.0.55")
    http.module("proxy_http_reverse")
    try:
        r = http.GET("/reverse/nonesuch/file%25")
        assert t_cmp(r.status_code, 404), "reverse proxy URI decoding issue, PR 15207"
    finally:
        http.module(None)


@need_module("proxy", "setenvif")
def test_proxy_not_proxied(http):
    http.module("proxy_http_reverse")
    try:
        r = http.GET("/reverse/notproxy/local.html")
        assert t_cmp(r.status_code, 200), "ProxyPass not-proxied request"
        assert t_cmp(r.text.rstrip("\n"), "hello world"), \
            "ProxyPass not-proxied content OK"
    finally:
        http.module(None)


@need_module("proxy", "setenvif")
def test_proxy_cookie_rewrite(http):
    if not (http.have_min_apache_version("2.4.34") and http.have_module("lua")):
        pytest.skip("needs mod_lua + httpd >= 2.4.34")
    http.module("proxy_http_reverse")
    try:
        r = http.GET("/reverse/modules/lua/setheaderfromparam.lua?"
                     "HeaderName=Set-Cookie&HeaderValue="
                     "fakedomain%3Dlocal%3Bdomain%3Dlocal")
        assert t_cmp(r.status_code, 200), "Lua executed"
        assert t_cmp(r.headers.get("Set-Cookie"), "fakedomain=local;domain=remote")

        r = http.GET("/reverse/modules/lua/setheaderfromparam.lua?"
                     "HeaderName=Set-Cookie&HeaderValue="
                     "fakepath%3D%2Flocal%3Bpath%3D%2Flocal")
        assert t_cmp(r.status_code, 200), "Lua executed"
        assert t_cmp(r.headers.get("Set-Cookie"), "fakepath=/local;path=/remote")

        r = http.GET("/reverse/modules/lua/setheaderfromparam.lua?"
                     "HeaderName=Set-Cookie&HeaderValue="
                     "domain%3Dlocal%3Bpath%3D%2Flocal%3bfoo%3Dbar")
        assert t_cmp(r.status_code, 200), "Lua executed"
        assert t_cmp(r.headers.get("Set-Cookie"), "domain=remote;path=/remote;foo=bar")
    finally:
        http.module(None)


@need_module("proxy", "setenvif")
def test_proxy_redirect_rewrite(http):
    if not http.have_module("alias"):
        pytest.skip("no mod_alias")
    http.module("proxy_http_reverse")
    try:
        r = http.GET("/reverse/perm")
        assert t_cmp(r.status_code, 301), "reverse proxy of redirect"
        assert t_cmp(r.headers.get("Location"),
                     re.compile(r"http://[^/]*/reverse/alias")), \
            "reverse proxy rewrote redirect"

        if http.have_module("proxy_balancer"):
            http.module("proxy_http_balancer")
            hostport = http.hostport()
            r = http.GET("/pr45434/redirect-me")
            assert t_cmp(r.status_code, 301), "reverse proxy of redirect via balancer"
            assert t_cmp(r.headers.get("Location"),
                         f"http://{hostport}/pr45434/5.html"), \
                "reverse proxy via balancer rewrote redirect"
    finally:
        http.module(None)


@need_module("proxy", "setenvif")
@pytest.mark.skipif(sys.platform == "win32", reason="AF_UNIX not available on Windows")
def test_proxy_uds(http):
    if not http.have_min_apache_version("2.4.7"):
        pytest.skip("UDS requires httpd >= 2.4.7")
    socket_path = "/tmp/test-ptf.sock"
    marker = socket_path + ".marker"
    for p in (socket_path, marker):
        try:
            os.unlink(p)
        except OSError:
            pass

    def uds_server():
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(socket_path)
        srv.listen(1024)
        open(marker, "w").close()
        srv.settimeout(15)
        try:
            conn, _ = srv.accept()
            conn.recv(4096)
            conn.sendall(b"HTTP/1.0 200 OK\r\n"
                         b"Content-Type: text/plain\r\n\r\n"
                         b"hello world\n")
            conn.close()
        except OSError:
            pass
        finally:
            srv.close()
            for p in (socket_path, marker):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    t = threading.Thread(target=uds_server, daemon=True)
    t.start()
    for _ in range(50):
        if os.path.exists(marker):
            break
        time.sleep(0.2)
    time.sleep(1)

    http.module("proxy_http_reverse")
    try:
        r = http.GET("/uds/")
        assert t_cmp(r.status_code, 200), "ProxyPass UDS path"
        assert t_cmp(r.text.rstrip("\n"), "hello world"), "UDS content OK"
    finally:
        http.module(None)
        t.join(timeout=5)


@need_module("proxy", "setenvif")
def test_proxy_mapping_servlet(http):
    if not http.have_min_apache_version("2.4.49"):
        pytest.skip("mapping=servlet requires httpd >= 2.4.49")
    http.module("proxy_http_reverse")
    try:
        for url in ("/notexisting/../mapping/mapping.html",
                    "/notexisting/..;/mapping/mapping.html",
                    "/mapping/mapping.html"):
            r = http.GET(url)
            assert t_cmp(r.status_code, 200), f"proxy mapping=servlet {url}"
    finally:
        http.module(None)
