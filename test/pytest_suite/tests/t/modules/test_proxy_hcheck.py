r"""Tests for mod_proxy_hcheck.

The backends are plain socket servers started here (not httpd), so each test
controls exactly what the health check sees.  Worker state is read from the
balancer-manager of the t/conf/proxy_hcheck.conf.in vhost: "Ok" while the
worker is healthy, "HcFl" once a health check has failed it.
"""

import re
import shutil
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

from apache_pytest import need_module

need = need_module("proxy_hcheck", "proxy_balancer", "proxy_http", "watchdog")


def conf_port(http, name):
    conf = Path(http.vars("t_logs")).parent / "conf" / "proxy_hcheck.conf"
    m = re.search(rf"Define HC_{name}_PORT (\d+)", conf.read_text())
    assert m, f"HC_{name}_PORT not found in {conf}"
    return int(m.group(1))


class Backend:
    """A TCP server that records each request head and answers via respond()."""

    def __init__(self, port, respond, tls=None):
        self.requests = []          # [(method, target, {lower-case header: value})]
        self.sni = []               # server names seen in TLS ClientHellos (None = none)
        self.respond = respond      # (backend, request) -> bytes or an iterable of them
        self.stopping = False
        self.tls = None
        if tls:
            self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls.load_cert_chain(*tls)
            self.tls.sni_callback = lambda sock, name, ctx: self.sni.append(name)
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                data = b""
                conn = self.request
                conn.settimeout(5)
                if outer.tls:
                    try:
                        conn = outer.tls.wrap_socket(conn, server_side=True)
                    except (ssl.SSLError, OSError):
                        return
                self.request = conn
                try:
                    while b"\r\n\r\n" not in data:
                        chunk = self.request.recv(4096)
                        if not chunk:
                            return
                        data += chunk
                except OSError:
                    return
                lines = data.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
                method, target, _ = lines[0].split(" ", 2)
                headers = {}
                for ln in lines[1:]:
                    k, _, v = ln.partition(":")
                    headers[k.strip().lower()] = v.strip()
                req = (method, target, headers)
                outer.requests.append(req)
                try:
                    out = outer.respond(outer, req)
                    if isinstance(out, (bytes, bytearray)):
                        out = [out]
                    for chunk in out:               # a generator may stream, slowly
                        if outer.stopping:
                            break
                        self.request.sendall(chunk)
                except OSError:
                    pass

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = Server(("127.0.0.1", port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.stopping = True
        self.server.shutdown()
        self.server.server_close()

    def targets(self):
        return [t for _, t, _ in self.requests]


def ok_response(backend, req):
    return (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


def worker_status(http, port):
    """The balancer-manager's status text for the worker on port <port>."""
    r = http.GET("/balancer-manager")
    assert r.status_code == 200, "balancer-manager not reachable"
    needle = re.compile(rf":{port}\b")
    for row in re.split(r"</tr>", r.text):
        if needle.search(row):
            for cell in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S):
                text = re.sub(r"<[^>]+>", "", cell).strip()
                if re.search(r"\b(Init|Ok|Dis|Stop|HcFl|Err)\b", text):
                    return text
    return None


def wait_until(fn, timeout, interval=0.3):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    return last


def is_ok(http, port):
    st = worker_status(http, port) or ""
    return "Ok" in st and "HcFl" not in st


def goes_bad(http, backend, port, bad):
    """Start from a healthy worker, then make the backend misbehave.

    A worker whose backend is not up yet is already failing, so "it is failing"
    proves nothing: first see it pass, and only then switch the response."""
    backend.respond = ok_response
    assert wait_until(lambda: is_ok(http, port), 20), (
        f"worker never became healthy: {worker_status(http, port)!r}")
    backend.respond = bad
    return wait_until(lambda: "HcFl" in (worker_status(http, port) or ""), 20)


@pytest.fixture
def hc_http(http):
    http.module("proxy_hcheck")
    try:
        yield http
    finally:
        http.module(None)


@need
def test_complete_response_keeps_worker_healthy(hc_http):
    """Control: a proper response passes the health check."""
    port = conf_port(hc_http, "HDR")
    b = Backend(port, ok_response)
    try:
        assert wait_until(lambda: b.requests, 15), "no health check arrived"
        time.sleep(3)
        assert "HcFl" not in (worker_status(hc_http, port) or "")
        assert "Ok" in (worker_status(hc_http, port) or "")
    finally:
        b.close()


@need
def test_truncated_response_headers_fail_the_check(hc_http):
    """A response whose headers end at EOF, without the blank line that
    terminates them, is not a valid response.  It used to be accepted, so a
    backend that was cutting its responses short was reported healthy."""
    port = conf_port(hc_http, "HDR")

    def truncated(backend, req):
        return b"HTTP/1.1 200 OK\r\nServer: broken\r\n"   # ...and closes

    b = Backend(port, ok_response)
    try:
        assert goes_bad(hc_http, b, port, truncated), (
            f"truncated headers passed: {worker_status(hc_http, port)!r}")
    finally:
        b.close()


def manager_post(http, balancer, query):
    """POST to the vhost's balancer-manager (the nonce comes from its page)."""
    r = http.GET("/balancer-manager")
    assert r.status_code == 200, "balancer-manager not reachable"
    m = re.search(rf"b={balancer}[^\"]*?nonce=([0-9a-fA-F-]+)", r.text.replace("&amp;", "&"))
    assert m, f"no nonce for balancer://{balancer}"
    v = http.vars()
    port = http.vhost_port("proxy_hcheck")
    referer = {"Referer": f"http://{v['servername']}:{port}/balancer-manager"}
    return http.POST("/balancer-manager",
                     content=(query + "&nonce=" + m.group(1)).encode(),
                     headers=referer)


@need
def test_changed_probe_uri_is_used(hc_http):
    """The probe URI is read from the worker when the health check is first set
    up, and was never looked at again, so changing it in the balancer-manager
    had no effect on what the backend saw."""
    port = conf_port(hc_http, "URI")
    b = Backend(port, ok_response)
    try:
        assert wait_until(lambda: "/old" in b.targets(), 15), "no /old probe"

        r = manager_post(hc_http, "hcuri", f"w=http://127.0.0.1:{port}&b=hcuri&w_hu=/new")
        assert r.status_code == 200
        assert "<td>/new</td>" in hc_http.GET("/balancer-manager").text, (
            "the balancer-manager did not store the new URI")

        mark = len(b.requests)
        assert wait_until(lambda: "/new" in b.targets()[mark:], 15), (
            f"probes after the change still went to {sorted(set(b.targets()[mark:]))}")
    finally:
        b.close()


def make_cert(directory, name):
    """A self-signed certificate for `name`; returns (certfile, keyfile) or None."""
    for exe in (shutil.which("openssl"), "/opt/homebrew/opt/openssl@3/bin/openssl",
                "/opt/local/bin/openssl"):
        if not exe:
            continue
        cert, key = f"{directory}/{name}.crt", f"{directory}/{name}.key"
        r = subprocess.run(
            [exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-subj", f"/CN={name}", "-addext", f"subjectAltName=DNS:{name}",
             "-keyout", key, "-out", cert],
            capture_output=True)
        if r.returncode == 0:
            return cert, key
    return None


@pytest.fixture
def certs():
    with tempfile.TemporaryDirectory() as d:
        bad, good = make_cert(d, "wrong.invalid"), make_cert(d, "localhost")
        if not bad or not good:
            pytest.skip("no openssl able to make a test certificate")
        yield {"bad": bad, "good": good}


def tls_need(http):
    if not http.have_module("ssl"):
        pytest.skip("mod_ssl is required")


@need
def test_https_probe_sends_sni_and_checks_the_name(hc_http, certs):
    """A health check of an https worker used to send no SNI and skip the host
    name check, so a backend presenting the certificate of another host passed
    even though real requests to it are refused."""
    tls_need(hc_http)
    port = conf_port(hc_http, "TLSBAD")
    b = Backend(port, ok_response, tls=certs["bad"])
    try:
        assert wait_until(lambda: b.sni, 15), "no TLS handshake reached the backend"
        assert "localhost" in b.sni, f"SNI seen by the backend: {b.sni}"
        # The worker starts out failing (nothing was listening yet), so what
        # matters is that, with handshakes happening, it never turns healthy.
        assert not wait_until(lambda: is_ok(hc_http, port), 8), (
            "wrong-host certificate passed the check: "
            f"{worker_status(hc_http, port)!r}")
    finally:
        b.close()


@need
def test_https_probe_with_matching_certificate_passes(hc_http, certs):
    """Control for the above: the right certificate keeps the worker healthy."""
    tls_need(hc_http)
    port = conf_port(hc_http, "TLSGOOD")
    b = Backend(port, ok_response, tls=certs["good"])
    try:
        assert wait_until(lambda: b.requests, 15), "no health check request arrived"
        time.sleep(3)
        status = worker_status(hc_http, port) or ""
        assert "Ok" in status and "HcFl" not in status, status
        assert "localhost" in b.sni
    finally:
        b.close()


# ---- limits on what a probe accepts from a backend ----------------------------

@need
def test_response_with_too_many_headers_fails_the_check(hc_http):
    port = conf_port(hc_http, "MANYHDR")

    def many(backend, req):
        hdrs = b"".join(b"X-Filler-%d: v\r\n" % i for i in range(2000))
        return b"HTTP/1.1 200 OK\r\n" + hdrs + b"Content-Length: 0\r\nConnection: close\r\n\r\n"

    b = Backend(port, ok_response)
    try:
        assert goes_bad(hc_http, b, port, many), (
            f"2000 response headers were accepted: {worker_status(hc_http, port)!r}")
    finally:
        b.close()


@need
def test_endless_response_is_cut_off(hc_http):
    """A backend that keeps sending (a byte every half second here) never trips
    a per-read timeout.  The probe needs an overall deadline (the worker's
    timeout, 2s here) or it holds a checking thread, and keeps growing its
    buffer, for as long as the backend cares to go on."""
    port = conf_port(hc_http, "SLOW")

    def endless(backend, req):
        yield b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
        while True:
            time.sleep(0.5)
            yield b"x"

    b = Backend(port, ok_response)
    try:
        assert goes_bad(hc_http, b, port, endless), (
            f"an endless response was never cut off: {worker_status(hc_http, port)!r}")
    finally:
        b.close()


def big_ok(size):
    def respond(backend, req):
        yield (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % size)
        sent = 0
        while sent < size:
            n = min(65536, size - sent)
            yield b"x" * n
            sent += n
    return respond


@need
def test_large_body_is_not_kept_for_a_condition(hc_http):
    """With a condition on the body, a probe keeps the body in memory to evaluate
    it.  A 3MB body is more than that is allowed to take, and fails the check."""
    port = conf_port(hc_http, "BIGEXPR")
    b = Backend(port, ok_response)
    try:
        assert goes_bad(hc_http, b, port, big_ok(3 * 1024 * 1024)), (
            f"a 3MB body was kept and evaluated: {worker_status(hc_http, port)!r}")
    finally:
        b.close()


@need
def test_large_body_without_a_condition_is_fine(hc_http):
    """Control: with no condition the body is not needed, is read and dropped,
    and the check passes as before."""
    port = conf_port(hc_http, "BIGPLAIN")
    b = Backend(port, big_ok(3 * 1024 * 1024))
    try:
        assert wait_until(lambda: len(b.requests) >= 2, 15), "probes stopped arriving"
        status = worker_status(hc_http, port) or ""
        assert "Ok" in status and "HcFl" not in status, status
    finally:
        b.close()


# ---- the probe's request line ---------------------------------------------------

@need
@pytest.mark.parametrize("name,expected", [
    ("PATHA", "/ping"),         # http://host:port        + hcuri "ping"
    ("PATHB", "/app/ping"),     # http://host:port/app    + hcuri "/ping"
    ("PATHC", "/app/ping"),     # http://host:port/app/   + hcuri "ping"
    ("PATHD", "/"),             # http://host:port        + no hcuri
    ("PATHE", "/app"),          # http://host:port/app    + no hcuri
    ("PATHF", "/app/"),         # http://host:port/app/   + no hcuri: kept as is
    ("PATHG", "/app/"),         # http://host:port/app    + hcuri "/"
])
def test_probe_path_joins_worker_path_and_hcuri(hc_http, name, expected):
    """One slash between the worker's path and hcuri, and a request target that
    starts with one: a bare "ping" used to be sent as "GET ping HTTP/1.0", and a
    path plus "/ping" as "/app//ping"."""
    b = Backend(conf_port(hc_http, name), ok_response)
    try:
        assert wait_until(lambda: b.requests, 15), "no health check arrived"
        assert set(b.targets()) == {expected}, b.targets()
    finally:
        b.close()


@need
def test_check_worker_is_created_once(hc_http):
    """The cache of per-worker check state is looked up on every cycle; if the
    lookup were to miss, a new long-lived check worker would be created each
    time.  (Guards the lifetime of the cache's keys.)"""
    port = conf_port(hc_http, "URI")
    error_log = Path(hc_http.vars("t_logs")) / "error_log"
    b = Backend(port, ok_response)
    try:
        assert wait_until(lambda: len(b.requests) >= 5, 20), "too few health checks"
    finally:
        b.close()
    session_start = int(hc_http.vars("session_log_start") or 0)
    with error_log.open("r", errors="replace") as fh:
        fh.seek(session_start)
        created = [ln for ln in fh if "Creating hc worker" in ln
                   and f"127.0.0.1:{port}" in ln]
    assert len(created) == 1, created
