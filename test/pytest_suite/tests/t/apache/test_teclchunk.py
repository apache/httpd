r"""Translated from t/apache/teclchunk.t -- Transfer-Encoding + Content-Length.

Sends a chunked POST that also carries a Content-Length header (request
smuggling shape). Since 2.4.47 the server must ignore the Content-Length, treat
the body as the single "0" chunk, run the trailer, and NOT treat the trailing
bytes as a second (404) request. Asserts: 200 status, trailer echoes the
sentinel, and no further response line is produced.

Perl original:
    if (!have_min_apache_version('2.4.47')) { skip }
    plan tests => 4, ['echo_post_chunk'];
    $sock->print("POST /echo_post_chunk HTTP/1.1\r\n");
    $sock->print("Host: localhost\r\nContent-Length: 77\r\n");
    $sock->print("Transfer-Encoding: chunked\r\n\r\n");
    $sock->print("0\r\nX-Chunk-Trailer: $$\r\n\r\n");
    $sock->print("GET /i_do_not_exist... HTTP/1.1\r\nHost: localhost\r\n");
    ... ok status == "HTTP/1.1 200 OK"; ok trailer == $$; ok next line "NO".
"""

import os

import pytest

from apache_pytest import need_module, t_cmp


@need_module("echo_post_chunk")
def test_teclchunk(http):
    if not http.have_min_apache_version("2.4.47"):
        pytest.skip("Not supported yet")

    pid = str(os.getpid())

    # 'default' in Apache::TestRequest means the main server port.
    sock = http.vhost_socket()
    assert sock

    sock.print("POST /echo_post_chunk HTTP/1.1\r\n")
    sock.print("Host: localhost\r\n")
    sock.print("Content-Length: 77\r\n")
    sock.print("Transfer-Encoding: chunked\r\n")
    sock.print("\r\n")
    sock.print("0\r\n")
    sock.print(f"X-Chunk-Trailer: {pid}\r\n")
    sock.print("\r\n")
    sock.print("GET /i_do_not_exist_in_your_wildest_imagination HTTP/1.1\r\n")
    sock.print("Host: localhost\r\n")

    # Read the status line.
    response = (sock.getline() or "").rstrip()
    assert t_cmp(response, "HTTP/1.1 200 OK"), "response codes"

    # Drain headers up to the blank line.
    while True:
        response = (sock.getline() or "").rstrip()
        if response == "":
            break

    # Complete the (deliberately) incomplete second request -- it MUST fail.
    sock.print("\r\n")
    sock.print("\r\n")

    # Read the trailer (pid).
    response = sock.getline()
    if response is not None:
        response = response.rstrip("\r\n")
    assert t_cmp(response, pid), "trailer (pid)"

    # Make sure we did NOT receive a 404 for the trailing bytes.
    response = (sock.getline() or "NO").rstrip()
    assert t_cmp(response, "NO"), "no response"
    sock.close()
