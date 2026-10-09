r"""Translated from t/apache/http_strict.t -- HttpProtocolOptions Strict/Unsafe.

Sends a large battery of hand-built (mostly malformed) requests to two vhosts:
http_unsafe (HttpProtocolOptions Unsafe Allow0.9 -- expect column 1) and
http_strict (Strict Require1.0 RegisteredMethods -- expect column 2, falling
back to column 1 when the strict expectation is undef). Each expectation is:

    >100  -> exact status code
    90    -> headerless HTTP/0.9 body (always pass)
    1     -> any 2xx/3xx success
    0     -> any >=400 error
    None  -> the server must drop the connection (no response)

Requests beginning with "R" are response-header tests: the remainder is
base64-encoded and sent to send_hdr.pl (needs CGI), which reflects it into the
response headers. A final block exercises obsolete header folding (/fold).

Perl original:
    plan tests => scalar(@test_cases)*2 + $test_fold*2, need_min_apache_version('2.2.32');
    foreach my $vhosts ((["http_unsafe"=>1], ["http_strict"=>2])) { ... }
    if ($test_fold) { $resp = GET("/fold"); ok 200; ok Foo =~ /Bar Baz/; }
"""

import base64
import socket
import time

import pytest

from apache_pytest import need_min_apache_version, need_module, t_cmp

# undef -> None (drop connection); ints are status / 0 / 1 / 90 sentinels.
# Each entry: (request, expect_unsafe, expect_strict_or_None, cond_key_or_None)
# cond_key: "underscore" gated on need_min_apache_version("2.4.34"),
#           "headers" gated on have_module("headers").
U = None
CASES = [
    ("GET / HTTP/1.0\r\n\r\n", 1, None, None),
    ("GET / HTTP/1.0\n\n", 1, 400, None),
    ("get / HTTP/1.0\r\n\r\n", 501, None, None),
    ("G ET / HTTP/1.0\r\n\r\n", 400, None, None),
    ("G\0ET / HTTP/1.0\r\n\r\n", 400, None, None),
    ("G/T / HTTP/1.0\r\n\r\n", 501, 400, None),
    ("GET /\0 HTTP/1.0\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\0\r\n\r\n", 400, None, None),
    ("GET\f/ HTTP/1.0\r\n\r\n", 400, None, None),
    ("GET\r/ HTTP/1.0\r\n\r\n", 400, None, None),
    ("GET\t/ HTTP/1.0\r\n\r\n", 400, None, None),
    ("GET / HTT/1.0\r\n\r\n", 0, None, None),
    ("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n", 1, None, None),
    ("GET / HTTP/2.0\r\nHost: localhost\r\n\r\n", 1, None, None),
    ("GET / HTTP/1.2\r\nHost: localhost\r\n\r\n", 1, None, None),
    ("GET / HTTP/1.11\r\nHost: localhost\r\n\r\n", 400, None, None),
    ("GET / HTTP/10.0\r\nHost: localhost\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0  \r\nHost: localhost\r\n\r\n", 200, 400, None),
    ("GET / HTTP/1.0 x\r\nHost: localhost\r\n\r\n", 400, None, None),
    ("GET / HTTP/\r\nHost: localhost\r\n\r\n", 0, None, None),
    ("GET / HTTP/0.9\r\n\r\n", 0, None, None),
    ("GET / HTTP/0.8\r\n\r\n", 0, None, None),
    ("GET /\x01 HTTP/1.0\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\nFoo: bar\r\n\r\n", 200, None, None),
    ("GET / HTTP/1.0\r\nFoo:bar\r\n\r\n", 200, None, None),
    ("GET / HTTP/1.0\r\nFoo: b\0ar\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\nFoo: b\x01ar\r\n\r\n", 200, 400, None),
    ("GET / HTTP/1.0\r\nFoo\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\nFoo bar\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\n: bar\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\nX: bar\r\n\r\n", 200, None, None),
    ("GET / HTTP/1.0\r\nFoo bar:bash\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\nFoo :bar\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\n Foo:bar\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\nF\x01o: bar\r\n\r\n", 200, 400, None),
    ("GET / HTTP/1.0\r\nF\ro: bar\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\nF\to: bar\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\nFo: b\tar\r\n\r\n", 200, None, None),
    ("GET / HTTP/1.0\r\nFo: bar\r\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\r", U, U, None),
    ("GET /\r\n", 90, U, None),
    ("GET /#frag HTTP/1.0\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\nHost: localhost\r\nHost: localhost\r\n\r\n", 200, 400, None),
    ("GET http://017700000001/ HTTP/1.0\r\n\r\n", 200, 400, None),
    ("GET http://0x7f.1/ HTTP/1.0\r\n\r\n", 200, 400, None),
    ("GET http://127.0.0.1/ HTTP/1.0\r\n\r\n", 200, None, None),
    ("GET http://127.01.0.1/ HTTP/1.0\r\n\r\n", 200, 400, None),
    ("GET http://%3127.0.0.1/ HTTP/1.0\r\n\r\n", 200, 400, None),
    ("GET / HTTP/1.0\r\nHost: localhost:80\r\nHost: localhost:80\r\n\r\n", 200, 400, None),
    ("GET / HTTP/1.0\r\nHost: localhost:80 x\r\n\r", 400, None, None),
    ("GET http://localhost:80/ HTTP/1.0\r\n\r\n", 200, None, None),
    ("GET http://localhost:80x/ HTTP/1.0\r\n\r\n", 400, None, None),
    ("GET http://localhost:80:80/ HTTP/1.0\r\n\r\n", 400, None, None),
    ("GET http://localhost::80/ HTTP/1.0\r\n\r\n", 400, None, None),
    ("GET http://foo\@localhost:80/ HTTP/1.0\r\n\r\n", 200, 400, None),
    ("GET http://[::1]/ HTTP/1.0\r\n\r\n", 1, None, None),
    ("GET http://[::1:2]/ HTTP/1.0\r\n\r\n", 1, None, None),
    ("GET http://[4712::abcd]/ HTTP/1.0\r\n\r\n", 1, None, None),
    ("GET http://[4712::abcd:1]/ HTTP/1.0\r\n\r\n", 1, None, None),
    ("GET http://[4712::abcd::]/ HTTP/1.0\r\n\r\n", 400, None, None),
    ("GET http://[4712:abcd::]/ HTTP/1.0\r\n\r\n", 1, None, None),
    ("GET http://[4712::abcd]:8000/ HTTP/1.0\r\n\r\n", 1, None, None),
    ("GET http://4713::abcd:8001/ HTTP/1.0\r\n\r\n", 400, None, None),
    ("GET / HTTP/1.0\r\nHost: [::1]\r\n\r\n", 1, None, None),
    ("GET / HTTP/1.0\r\nHost: [::1:2]\r\n\r\n", 1, None, None),
    ("GET / HTTP/1.0\r\nHost: [4711::abcd]\r\n\r\n", 1, None, None),
    ("GET / HTTP/1.0\r\nHost: [4711::abcd:1]\r\n\r\n", 1, None, None),
    ("GET / HTTP/1.0\r\nHost: [4711:abcd::]\r\n\r\n", 1, None, None),
    ("GET / HTTP/1.0\r\nHost: [4711::abcd]:8000\r\n\r\n", 1, None, None),
    ("GET / HTTP/1.0\r\nHost: 4714::abcd:8001\r\n\r\n", 200, 400, None),
    ("GET / HTTP/1.0\r\nHost: abc\xa0\r\n\r\n", 200, 400, None),
    ("GET / HTTP/1.0\r\nHost: abc\\foo\r\n\r\n", 400, None, None),
    ("GET http://foo/ HTTP/1.0\r\nHost: bar\r\n\r\n", 200, None, None),
    ("GET http://foo:81/ HTTP/1.0\r\nHost: bar\r\n\r\n", 200, None, None),
    ("GET http://[::1]:81/ HTTP/1.0\r\nHost: bar\r\n\r\n", 200, None, None),
    ("GET http://10.0.0.1:81/ HTTP/1.0\r\nHost: bar\r\n\r\n", 200, None, None),
    ("GET / HTTP/1.0\r\nHost: foo-bar.example.com\r\n\r\n", 200, None, None),
    ("GET / HTTP/1.0\r\nHost: foo_bar.example.com\r\n\r\n", 200, 200, "underscore"),
    ("GET http://foo_bar/ HTTP/1.0\r\n\r\n", 200, 200, "underscore"),
    # response-header tests (sent to send_hdr.pl): leading "R" marker.
    ("RFoo: bar", 200, None, None),
    ("RFoo:", 200, None, None),
    ("R: bar", 500, None, None),
    ("RF\0oo: bar", 500, None, None),
    ("RF\x01oo: bar", 500, None, None),
    ("RF\noo: bar", 500, None, None),
    ("RFoo: b\tar", 200, None, None),
    ("RFoo: b\x01ar", 500, None, None),
    # regression: bad Header value + bad field name must not recurse.
    ("GET /regression-header HTTP/1.1\r\nHost:localhost\r\n\r\n", 500, 500, "headers"),
]

VHOSTS = [("http_unsafe", 1), ("http_strict", 2)]


def _status_code(data: str):
    if not data:
        return None
    first = data.split("\n", 1)[0].strip()
    parts = first.split()
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        return int(parts[1])
    return None


def _check(code, expect):
    if expect is None:
        assert code is None, f"expected dropped connection, got {code}"
    elif expect > 100:
        assert t_cmp(code, expect), f"expected {expect}, got {code}"
    elif expect == 90:
        pass  # headerless HTTP/0.9 body -- always pass
    elif expect:
        assert code is not None and 200 <= code < 400, f"expected success, got {code}"
    else:
        assert code is not None and code >= 400, f"expected error, got {code}"


@need_min_apache_version("2.2.32")
@pytest.mark.parametrize("vhost,col", VHOSTS, ids=[v[0] for v in VHOSTS])
@pytest.mark.parametrize(
    "case", CASES, ids=[f"{i}" for i in range(len(CASES))]
)
def test_http_strict(http, vhost, col, case):
    req, exp_unsafe, exp_strict, cond = case
    expect = exp_unsafe if col == 1 else (exp_strict if exp_strict is not None else exp_unsafe)

    if cond == "underscore" and not http.have_min_apache_version("2.4.34"):
        pytest.skip("Test prerequisites are not met")
    if cond == "headers" and not http.have_module("headers"):
        pytest.skip("Test prerequisites are not met")

    decoded = None
    if req.startswith("R"):
        if not (http.have_module("cgi") or http.have_module("cgid")):
            pytest.skip("Skipping test without CGI module")
        decoded = req[1:]
        q = base64.b64encode(decoded.encode("latin-1")).decode("ascii")
        req = f"GET /apache/http_strict/send_hdr.pl?{q} HTTP/1.0\r\n\r\n"

    sock = http.vhost_socket(vhost)
    assert sock, "failed to connect"

    sock.print(req)
    # Half-close the write side (Perl $sock->shutdown(1)) so the server stops
    # waiting for more request bytes and either responds or drops the connection.
    try:
        sock._sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    time.sleep(0.1)
    # A "drop the connection" case (expect is None) may surface as a reset while
    # reading -- treat that as an empty response (no status code).
    try:
        data = sock.read()
    except OSError:
        data = ""
    code = _status_code(data)
    _check(code, expect)
    sock.close()


@need_min_apache_version("2.4.26")
@need_module("fold")
def test_http_strict_fold(http):
    r"""Obsolete header folding: GET /fold should yield Foo: 'Bar Baz'.

    The fold C-module emits ``Foo: Bar\r\n Baz`` (an obsolete folded header)
    which the unfolding server should join to ``Bar Baz``. Read it over a raw
    socket: httpx rejects obsolete line folding, so the GET path can't be used.
    """
    sock = http.vhost_socket()
    assert sock

    sock.print("GET /fold HTTP/1.0\r\n\r\n")
    try:
        sock._sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    data = sock.read()
    sock.close()

    assert t_cmp(_status_code(data), 200), "fold response 200"
    # Headers are unfolded by the server; find the Foo header value.
    head = data.split("\r\n\r\n", 1)[0]
    head = head.replace("\r\n ", " ").replace("\r\n\t", " ")  # join any folding
    foo = None
    for line in head.split("\r\n"):
        if line.lower().startswith("foo:"):
            foo = line.split(":", 1)[1].strip()
            break
    assert foo is not None and "Bar Baz" in foo, "folded Foo header"
