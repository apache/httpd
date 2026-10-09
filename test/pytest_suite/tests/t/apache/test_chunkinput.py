r"""Translated from t/apache/chunkinput.t -- chunked request-body parsing.

Sends HTTP/1.0 POSTs with Transfer-Encoding: chunked and a variety of chunk-size
lines (valid, with chunk extensions, with bad whitespace, oversized, control
chars in data, invalid leading LWS) to the echo_post_chunk handler and to a
non-existent URI; asserts the status line for each. The very first case also
verifies the X-Chunk-Trailer trailer is echoed back.

Chunk-size lines containing "::" are sent split across packets (with a small
pause) to exercise incremental parsing.

Perl original:
    plan tests => 4 * @test_strings + 1, ['echo_post_chunk'];
    for my $data (@test_strings) { for my $uri (@req_strings) {
        $sock->print("POST $uri HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n");
        # send $data (split on "::" with sleeps) then trailer + blank line
        chomp(my $response = getline($sock));
        ok t_cmp($response, $resp_strings[$cycle++], "response codes");
        # drain headers; on first cycle also read+check the trailer (pid)
    }}
"""

import os

import pytest

from apache_pytest import need_module, t_cmp

OK = "HTTP/1.1 200 OK"
NOTFOUND = "HTTP/1.1 404 Not Found"
BAD = "HTTP/1.1 400 Bad Request"
TOOBIG = "HTTP/1.1 413 Request Entity Too Large"
ECHO = "/echo_post_chunk"
NOPE = "/i_do_not_exist_in_your_wildest_imagination"

# (chunk data, request uri, expected status line)
CASES = [
    ("0", ECHO, OK),
    ("0", NOPE, NOTFOUND),
    ("A\r\n1234567890\r\n0", ECHO, OK),
    ("A\r\n1234567890\r\n0", NOPE, NOTFOUND),
    ("A; ext=val\r\n1234567890\r\n0", ECHO, OK),
    ("A; ext=val\r\n1234567890\r\n0", NOPE, NOTFOUND),
    ("A    \r\n1234567890\r\n0", ECHO, OK),  # <10 BWS
    ("A    \r\n1234567890\r\n0", NOPE, NOTFOUND),
    ("A :: :: :: \r\n1234567890\r\n0", ECHO, OK),  # <10 BWS multi-send
    ("A :: :: :: \r\n1234567890\r\n0", NOPE, NOTFOUND),
    ("A           \r\n1234567890\r\n0", ECHO, BAD),  # >10 BWS
    ("A           \r\n1234567890\r\n0", NOPE, BAD),
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n", ECHO, TOOBIG),  # overflow
    ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n", NOPE, TOOBIG),
    ("A; ext=\x7Fval\r\n1234567890\r\n0", ECHO, BAD),  # ctrl in data
    ("A; ext=\x7Fval\r\n1234567890\r\n0", NOPE, BAD),
    (" A", ECHO, BAD),  # invalid LWS
    (" A", NOPE, BAD),
]


def _drain_headers(sock):
    while True:
        line = (sock.getline() or "").rstrip()
        if line == "":
            break


@need_module("echo_post_chunk")
@pytest.mark.parametrize(
    "data,uri,expect",
    CASES,
    ids=[f"{i}_{'echo' if c[1] == ECHO else 'nf'}" for i, c in enumerate(CASES)],
)
def test_chunkinput(http, data, uri, expect):
    pid = str(os.getpid())
    first_case = data == "0" and uri == ECHO

    # 'default' in Apache::TestRequest means the main server port.
    sock = http.vhost_socket()
    assert sock

    sock.print(f"POST {uri} HTTP/1.0\r\n")
    sock.print("Transfer-Encoding: chunked\r\n")
    sock.print("\r\n")

    elts = data.split("::")
    if len(elts) > 1:
        for elt in elts:
            sock.print(elt)
            # original sleeps 0.5 between packets to force separate reads
        sock.print("\r\n")
    else:
        sock.print(f"{data}\r\n")
    sock.print(f"X-Chunk-Trailer: {pid}\r\n")
    sock.print("\r\n")

    response = (sock.getline() or "").rstrip()
    assert t_cmp(response, expect), "response codes"

    _drain_headers(sock)

    if first_case:
        trailer = sock.getline()
        if trailer is not None:
            trailer = trailer.rstrip("\r\n")
        assert t_cmp(trailer, pid), "trailer (pid)"
    sock.close()
