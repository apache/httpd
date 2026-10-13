import re
import socket
from threading import Thread

import pytest

from pyhttpd.conf import HttpdConf

# mod_substitute keeps the start of an unfinished line in ctx->linebb across
# filter invocations.  When a line grows past SubstituteMaxLineLength the
# filter bails out with "goto err" without clearing ctx->linebb, so any
# buckets left there still reference the data they pointed at.  Behind a
# reverse proxy those are transient buckets over the backend connection's
# read buffers; the proxy frees them when the response ends, and the EOS
# that follows makes the filter flatten the stale buckets -- a use-after-free.
#
# A backend that streams with Transfer-Encoding: chunked reaches this: each
# chunk is read separately, so a line longer than the limit is accumulated
# in ctx->linebb over several calls before the limit trips.

# >1MB line (no newline) so it exceeds the default SubstituteMaxLineLength.
LONG_LINE = b"A" * (1200 * 1024)
BODY = b"<p>start</p>\n" + LONG_LINE + b"\n<p>end</p>\n"


class _ChunkedBackend:

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
                try:
                    c.recv(4096)
                    c.sendall(b"HTTP/1.1 200 OK\r\n"
                              b"Content-Type: text/html\r\n"
                              b"Transfer-Encoding: chunked\r\n\r\n")
                    for i in range(0, len(BODY), 16000):
                        part = BODY[i:i + 16000]
                        c.sendall(b"%x\r\n" % len(part) + part + b"\r\n")
                    c.sendall(b"0\r\n\r\n")
                except OSError:
                    pass

    def stop(self):
        self._done = True
        self._thread.join(timeout=5)
        self._sock.close()


class TestSubstituteProxy:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.require(env.has_shared_module("proxy")
                    and env.has_shared_module("proxy_http"),
                    "mod_proxy/mod_proxy_http not available",
                    dep="mod_proxy",
                    detected=f"no mod_proxy.so in {env.libexec_dir}")
        backend = _ChunkedBackend(env.http_port2)
        # MaxMemFree 1 returns freed memory to the C library immediately, so
        # that an ASan build detects the stale read instead of silently
        # reusing a cached block.
        conf = HttpdConf(env, extras={"base": ["MaxMemFree 1"]})
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port,
                         doc_root="htdocs", with_ssl=False)
        # only below /proxy/, so that the check whether the server is up
        # (a GET of /) does not go to the backend
        conf.add([
            f"ProxyPass /proxy/ http://127.0.0.1:{env.http_port2}/",
            "<Location /proxy/>",
            "    AddOutputFilterByType SUBSTITUTE text/html",
            '    Substitute "s/start/begin/"',
            "</Location>",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield
        backend.stop()

    # A line over the limit must be rejected without the child aborting.
    def test_filters_005_01(self, env):
        url = env.mkurl("http", "test1", "/proxy/x")
        pos = env.httpd_error_log.current_pos()
        env.curl_get(url)
        # an ASan build reports the stale read, another build may have the
        # child die on a signal, which the parent logs
        crashed = env.httpd_error_log.wait_for(
            re.compile(r".*(==\d+==ERROR: AddressSanitizer|exit signal).*"),
            pos, timeout=2)
        assert not crashed, "child crashed or sanitizer fired"
        # the server must still be serving
        r2 = env.curl_get(url)
        assert r2.exit_code == 0, f"no answer after the first request: {r2}"
        env.httpd_error_log.ignore_recent(lognos=["AH01328", "AH01110"])
