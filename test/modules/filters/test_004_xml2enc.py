import re
import socket
from threading import Thread

import pytest

from pyhttpd.conf import HttpdConf

# mod_xml2enc buffers the start of a response to sniff its charset, and
# carries a partial multibyte sequence over to the next brigade.  A backend
# failing part way through a response makes mod_proxy_http send an error
# bucket (but no EOS) down the chain, and a CGI script timing out makes the
# read of the body fail; neither must abort the child, and a response which
# ends with half a character must still end.

# More than mod_xml2enc buffers (BUF_MIN) before it sniffs the charset.
BIG5_BODY = b"<html><body>" + b"a" * 5000


def _response(path):
    if path.startswith("/short"):
        # announces more than it sends, then closes
        return (b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                b"Content-Length: 1000\r\n"
                b"\r\n"
                b"<html><body>partial")
    if path.startswith("/big5-"):
        # converted by mod_xml2enc (libxml2 has no Big5), ending with half
        # a character; /big5-short then closes early
        body = BIG5_BODY + b"\xa4"
        clen = len(body) + (1000 if path.startswith("/big5-short") else 0)
        return (b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html; charset=Big5\r\n"
                b"Content-Length: %d\r\n"
                b"\r\n" % clen) + body
    return (b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 3\r\n"
            b"\r\n"
            b"ok\n")


class _Backend:

    def __init__(self, port):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(4)
        self._sock.settimeout(0.5)
        self._done = False
        self._thread = Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._done:
            try:
                c, _ = self._sock.accept()
            except socket.timeout:
                continue
            with c:
                data = c.recv(4096)
                path = data.split(b" ")[1].decode() if b" " in data else "/"
                c.sendall(_response(path))

    def stop(self):
        self._done = True
        self._thread.join(timeout=5)
        self._sock.close()


def _get_raw(env, path):
    with socket.create_connection(("127.0.0.1", int(env.http_port))) as sock:
        sock.sendall((f"GET {path} HTTP/1.1\r\n"
                      f"Host: test1.{env.http_tld}\r\n"
                      f"Connection: close\r\n"
                      f"\r\n").encode())
        sock.settimeout(5)
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    return data


def _aborted_since(env, pos):
    # ap_assert() logs AH00102 before the child aborts
    return env.httpd_error_log.wait_for(re.compile(r".*AH00102: .*"), pos,
                                        timeout=0)


def _skip_without_big5(env, pos):
    # mod_xml2enc converts Big5 with apr_xlate, which may not support it
    if env.httpd_error_log.wait_for(re.compile(r".*AH01435: .*"), pos,
                                    timeout=0):
        env.httpd_error_log.ignore_recent(lognos=["AH01435", "AH01436",
                                                   "AH01110", "AH01220"])
        pytest.skip("apr_xlate cannot convert from Big5")


class TestXml2enc:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        for m in ["proxy", "proxy_http", "xml2enc", "proxy_html"]:
            env.require(env.has_shared_module(m), f"mod_{m} not available",
                        dep=f"mod_{m}",
                        detected=f"no mod_{m}.so in {env.libexec_dir}")
        backend = _Backend(env.http_port2)
        # Hand freed memory straight back to malloc, so that an ASan build
        # catches use of a bucket's data after the bucket is destroyed.
        conf = HttpdConf(env, extras={"base": ["MaxMemFree 1"]})
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port,
                         doc_root="htdocs/test1", with_ssl=False)
        conf.add([
            "ProxyPass /cgi/ !",
            f"ProxyPass / http://127.0.0.1:{env.http_port2}/",
            "ProxyHTMLEnable On",
            "<Location /cgi/>",
            "    AddHandler cgi-script .py",
            "    Options +ExecCGI",
            "    <IfModule cgi_module>",
            "        CGIScriptTimeout 1",
            "    </IfModule>",
            "    <IfModule cgid_module>",
            "        CGIDScriptTimeout 1",
            "    </IfModule>",
            "</Location>",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield
        backend.stop()

    # backend fails before mod_xml2enc has seen enough data to sniff the
    # charset: the error bucket must not be set aside (aborting the child)
    def test_filters_004_01(self, env):
        pos = env.httpd_error_log.current_pos()
        _get_raw(env, "/short")
        assert not _aborted_since(env, pos), "child aborted"
        # The data and the error reach ap_http_header_filter in the same
        # brigade, which then logs AH10390.
        env.httpd_error_log.ignore_recent(lognos=["AH01110", "AH10390"])

    # backend fails after a partial multibyte sequence
    def test_filters_004_02(self, env):
        pos = env.httpd_error_log.current_pos()
        raw = _get_raw(env, "/big5-short")
        assert not _aborted_since(env, pos), "child aborted"
        _skip_without_big5(env, pos)
        assert raw.startswith(b"HTTP/1.1 200 "), f"{raw[:200]!r}"
        env.httpd_error_log.ignore_recent(
            lognos=["AH01110"],
            matches=[r".*xml2enc: Discarding 1 unconverted bytes.*"])

    # a response ending with a partial multibyte sequence must still end
    def test_filters_004_03(self, env):
        pos = env.httpd_error_log.current_pos()
        r = env.curl_get(env.mkurl("http", "test1", "/big5-end"))
        _skip_without_big5(env, pos)
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        assert r.response["body"] == BIG5_BODY
        env.httpd_error_log.ignore_recent(
            matches=[r".*xml2enc: Discarding 1 unconverted bytes.*"])

    # a script stops writing before mod_xml2enc has enough to sniff: the
    # failed read must not abort the child, but be left to the rest of the
    # chain as without mod_xml2enc
    def test_filters_004_04(self, env):
        pos = env.httpd_error_log.current_pos()
        _get_raw(env, "/cgi/stall.py")
        assert not _aborted_since(env, pos), "child aborted"
        env.httpd_error_log.ignore_recent(
            lognos=["AH01220"],
            matches=[r".*xml2enc: failed reading data to sniff.*"])

    # a script stops writing after half a character, while mod_xml2enc is
    # reading the rest of it
    def test_filters_004_05(self, env):
        pos = env.httpd_error_log.current_pos()
        _get_raw(env, "/cgi/stall-big5.py")
        assert not _aborted_since(env, pos), "child aborted"
        _skip_without_big5(env, pos)
        env.httpd_error_log.ignore_recent(
            lognos=["AH01220"],
            matches=[r".*xml2enc: error reading data.*"])

    # input carried over from one read to the next must not point into a
    # bucket which has been freed by then
    def test_filters_004_06(self, env):
        pos = env.httpd_error_log.current_pos()
        r = env.curl_get(env.mkurl("http", "test1", "/cgi/split-big5.py"))
        _skip_without_big5(env, pos)
        assert not _aborted_since(env, pos), "child aborted"
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        # the output is the script's page converted, nothing lost or garbled
        # (an "a" after a lead byte is part of that character, not an "a")
        assert r.response["body"].count(b"a") == 31981, \
            f"{len(r.response['body'])} bytes"
        assert b"\xef\xbf\xbd" not in r.response["body"]
