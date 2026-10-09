r"""Translated from t/apache/hostcheck.t -- StrictHostCheck Host validation.

Sends HTTP/1.1 requests with various Host headers to two vhosts: "default" (no
strict host check, expect column 1) and "core" (StrictHostCheck ON, expect
column 2). Bogus/unlisted Host values are accepted (200) by default but rejected
(400) under strict checking; legitimate NVH names are accepted by both.

Perl original:
    plan tests => scalar(@test_cases) * 2, need_min_apache_version('2.4.49');
    foreach my $vhosts ((["default" => 1], ["core" => 2])) {
        foreach my $t (@test_cases) {
            my $expect = $t->[$expect_column];
            my $sock = Apache::TestRequest::vhost_socket($vhost);
            $sock->print($req); $sock->shutdown(1);
            my $response = HTTP::Response->parse($response_data);
            ok ($response->code == $expect);   # all expects > 100
        }
    }
"""

import socket

import pytest

from apache_pytest import need_min_apache_version, t_cmp

# (request, code on default vhost, code on strict-core vhost, description)
TEST_CASES = [
    ("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", 200, 400, "ok"),
    ("GET / HTTP/1.1\r\nHost: localhost:1\r\n\r\n", 200, 400, "port ignored"),
    ("GET / HTTP/1.1\r\nHost: notlisted\r\n\r\n", 200, 400, "name not listed"),
    ("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", 200, 400, "IP not in serveralias/servername"),
    ("GET / HTTP/1.1\r\nHost: default-strict\r\n\r\n", 200, 200, "NVH matches in default server"),
    ("GET / HTTP/1.1\r\nHost: nvh-strict\r\n\r\n", 200, 200, "NVH matches"),
    ("GET / HTTP/1.1\r\nHost: nvh-strict:1\r\n\r\n", 200, 200, "NVH matches port ignored"),
]

# (vhost module, index into the tuple for the expected code)
VHOSTS = [("default", 1), ("core", 2)]


def _status_code(data: str):
    if not data:
        return None
    first = data.split("\n", 1)[0].strip()
    parts = first.split()
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        return int(parts[1])
    return None


@need_min_apache_version("2.4.49")
@pytest.mark.parametrize("vhost,col", VHOSTS, ids=[v[0] for v in VHOSTS])
@pytest.mark.parametrize(
    "case", TEST_CASES, ids=[c[3].replace(" ", "_") for c in TEST_CASES]
)
def test_hostcheck(http, vhost, col, case):
    req, _, _, desc = case
    expect = case[col]

    # Apache::TestRequest 'default' == the main server port (not a named vhost).
    sock = http.vhost_socket(None if vhost == "default" else vhost)
    assert sock, "failed to connect"

    sock.print(req)
    # Half-close the write side (Perl $sock->shutdown(1)) so the server sees EOF
    # and completes/closes the HTTP/1.1 keepalive response instead of hanging.
    sock._sock.shutdown(socket.SHUT_WR)
    data = sock.read()
    code = _status_code(data)
    assert t_cmp(code, expect), f"{desc} (vhost {vhost})"
    sock.close()
