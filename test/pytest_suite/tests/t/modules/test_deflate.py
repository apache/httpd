r"""Translated from t/modules/deflate.t -- mod_deflate / mod_inflate round-trips.

mod_deflate is not built locally, so these SKIP via @need_module("deflate",
"echo_post"). When present: for each URI, GET it plain and gzipped, POST the
gzipped body back through the inflate (echo_post) endpoint and verify it
round-trips; verify a ``q=0`` Accept-Encoding is not compressed; and verify that
invalid/broken compressed request bodies are rejected (400 in >= 2.5,
``!!!ERROR!!!`` body in >= 2.4.5, else 200).

The mod_bucketeer URIs are added only when mod_bucketeer is present (it isn't
locally). The final CGI 304/Accept-Encoding raw-socket subtest runs only when a
CGI module and httpd >= 2.1.0 are present.

Perl original: plan tests => $tests, need 'deflate', 'echo_post';
"""

import socket

import pytest

from apache_pytest import need_module, t_cmp

DEFLATE_URIS = [
    "/modules/deflate/index.html",
    "/modules/deflate/apache_pb.gif",
    "/modules/deflate/asf_logo_wide.jpg",
    "/modules/deflate/zero.txt",
]
BUCKETEER_URIS = [
    "/modules/deflate/bucketeer/P.txt",
    "/modules/deflate/bucketeer/F.txt",
    "/modules/deflate/bucketeer/FP.txt",
    "/modules/deflate/bucketeer/FBP.txt",
    "/modules/deflate/bucketeer/BB.txt",
    "/modules/deflate/bucketeer/BBF.txt",
    "/modules/deflate/bucketeer/BFB.txt",
]
INFLATE_URI = "/modules/deflate/echo_post"

DEFLATE_HEADERS = {"Accept-Encoding": "gzip"}
DEFLATE_HEADERS_Q0 = {"Accept-Encoding": "gzip;q=0"}
INFLATE_HEADERS = {"Content-Encoding": "gzip"}


def _uris(http):
    uris = list(DEFLATE_URIS)
    if http.have_module("bucketeer"):
        uris += BUCKETEER_URIS
    return uris


@need_module("deflate", "echo_post")
def test_deflate(http):
    for uri in _uris(http):
        original = http.GET_BODY(uri)

        # httpx auto-decompresses, so GET_RAW reads the body undecoded to get
        # the actual gzip stream; re-POST it through the inflate input filter
        # (echo_post) and assert it round-trips back to the original.
        deflated = http.GET_RAW(uri, headers=DEFLATE_HEADERS)

        deflated_str_q0 = http.GET_BODY(uri, headers=DEFLATE_HEADERS_Q0)

        inflated = http.POST_BODY(uri and INFLATE_URI, content=deflated,
                                  headers=INFLATE_HEADERS)
        assert original == inflated
        assert original == deflated_str_q0

        resp = http.POST(INFLATE_URI, content=b"foo123456789012346",
                         headers=INFLATE_HEADERS)
        if http.have_min_apache_version("2.5"):
            assert t_cmp(resp.status_code, 400), \
                f"did not detect invalid compressed request body for {uri}"
        elif http.have_min_apache_version("2.4.5"):
            assert t_cmp(resp.text, "!!!ERROR!!!"), \
                f"did not detect invalid compressed request body for {uri}"
        else:
            assert t_cmp(resp.status_code, 200), f"invalid response for {uri}"

        broken = bytearray(deflated)
        offset = 20 if len(broken) > 35 else len(broken) - 15
        broken[offset:offset + 15] = b"123456789012345"
        resp = http.POST(INFLATE_URI, content=bytes(broken), headers=INFLATE_HEADERS)
        if http.have_min_apache_version("2.5"):
            assert t_cmp(resp.status_code, 400), \
                f"did not detect broken compressed request body for {uri}"
        elif http.have_min_apache_version("2.4.5"):
            import re
            assert t_cmp(resp.text, re.compile(r".*!!!ERROR!!!$")), \
                f"did not detect broken compressed request body for {uri}"
        else:
            assert t_cmp(resp.status_code, 200), f"invalid response for {uri}"


@need_module("deflate", "echo_post")
def test_deflate_304_eof(http):
    """304/deflate raw-socket subtest: requires a CGI module and httpd >= 2.1.0."""
    if not (http.have_module("cgid") or http.have_module("cgi")):
        pytest.skip("skipping 304/deflate tests without cgi")
    if not http.have_min_apache_version("2.1.0"):
        pytest.skip("skipping 304/deflate tests without httpd >= 2.1.0")

    sock = http.vhost_socket()
    assert sock.connected
    sock.print("GET /modules/cgi/not-modified.pl HTTP/1.0\r\n")
    sock.print("Accept-Encoding: gzip\r\n")
    sock.print("\r\n")
    sock._sock.shutdown(socket.SHUT_WR)

    import re
    response = (sock.getline() or "").rstrip()
    assert t_cmp(response, re.compile(r"HTTP/1\.. 304")), "response was 304"

    # drain headers up to the blank line
    while True:
        line = sock.getline()
        if line is None or line.rstrip() == "":
            break

    # no body should follow a 304
    body = sock.read()
    assert t_cmp(len(body), 0), "expect EOF after 304 header"
    sock.close()
