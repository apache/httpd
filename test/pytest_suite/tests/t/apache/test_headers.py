r"""Translated from t/apache/headers.t -- request-header normalization.

Sends GET requests carrying a single hand-built "Hello:" header (with various
whitespace / obsolete line-folding forms) to a CGI that echoes the environment,
and checks both that the request succeeds (200) and that the resulting
HTTP_HELLO env value is normalized as expected. The accepted forms depend on the
httpd version; this build (>=2.4.24) uses the "hasfix" header set where obsolete
folding collapses to a single space and trailing whitespace is trimmed.

Perl original:
    plan tests => (scalar keys %headers) * 3, need_cgi;
    foreach my $key (sort keys %headers) {
        my $sock = Apache::TestRequest::vhost_socket('default');
        $sock->print("GET /modules/cgi/env.pl HTTP/1.0\r\n");
        $sock->print($key); $sock->print("\r\n");
        chomp(my $response = getline($sock) || '');
        ok t_cmp($response, qr{HTTP/1\.. 200 OK}, "response success");
        # drain headers, then find "HTTP_HELLO = <value>" and compare
    }
"""

import re

import pytest

from apache_pytest import need_cgi, t_cmp

URI = "/modules/cgi/env.pl"

# "hasfix" header set (httpd >= 2.4.24 / 2.2.32): (header-line, expected value)
HEADERS = [
    ("Hello:World\r\n", "World"),
    ("Hello:  World\r\n", "World"),
    ("Hello:  World   \r\n", "World"),
    ("Hello:  World \t \r\n", "World"),
    ("Hello: Foo\r\n Bar\r\n", "Foo Bar"),
    ("Hello: Foo\r\n\tBar\r\n", "Foo Bar"),
    ("Hello: Foo\r\n    Bar\r\n", "Foo Bar"),
    ("Hello: Foo \t \r\n Bar\r\n", "Foo Bar"),
    ("Hello: Foo\r\n  \t Bar\r\n", "Foo Bar"),
]


@need_cgi()
@pytest.mark.parametrize(
    "header,value", HEADERS, ids=[repr(h[0]) for h in HEADERS]
)
def test_headers(http, header, value):
    # 'default' in Apache::TestRequest means the main server port.
    sock = http.vhost_socket()
    assert sock

    sock.print(f"GET {URI} HTTP/1.0\r\n")
    sock.print(header)
    sock.print("\r\n")

    response = (sock.getline() or "").rstrip()
    assert t_cmp(response, re.compile(r"HTTP/1\.. 200 OK")), "response success"

    # Drain response headers up to the blank line.
    while True:
        line = (sock.getline() or "").rstrip()
        if line == "":
            break

    # Find the echoed "HTTP_HELLO = <value>" line in the CGI body.
    found = False
    while True:
        line = sock.getline()
        if not line:
            break
        line = line.rstrip("\r\n")
        if line == "":
            continue
        parts = line.split(" = ", 1)
        if parts and parts[0] == "HTTP_HELLO":
            assert t_cmp(parts[1], value), "compare header Hello value"
            found = True
            break

    assert found, "HTTP_HELLO header echoed in response"
    sock.close()
