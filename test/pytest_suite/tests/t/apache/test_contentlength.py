r"""Translated from t/apache/contentlength.t -- Content-Length validation.

Sends HTTP/1.0 POSTs with assorted (some malformed) Content-Length values to
the eat_post handler (/echo_post) and to a non-existent URI, checking the status
line. Invalid lengths yield a failure status; the exact failure code depends on
the httpd version (400 Bad Request on the relevant 2.2/2.4 ranges, else 413).

Perl original:
    plan tests => 4 * @test_strings, ['eat_post'];
    for my $data (@test_strings) { for my $uri (@req_strings) {
        $sock->print("POST $uri HTTP/1.0\r\nContent-Length: $data\r\n\r\n\r\n");
        chomp(my $response = getline($sock) || '');
        ok t_cmp($response, $resp_strings[$cycle], ...);
    }}
"""

import pytest

from apache_pytest import need_module, t_cmp

OK = "HTTP/1.1 200 OK"
NOTFOUND = "HTTP/1.1 404 Not Found"
ECHO = "/echo_post"
NOPE = "/i_do_not_exist_in_your_wildest_imagination"

# (Content-Length value, request uri, expected-when-failure-is-400,
#  expected-when-failure-is-413)
#   "OK"/"NOTFOUND" are fixed; "FAIL" is replaced by the version-dependent code.
FAIL = "FAIL"
CASES = [
    ("", ECHO, FAIL),
    ("", NOPE, FAIL),
    ("0", ECHO, OK),
    ("0", NOPE, NOTFOUND),
    ("0000000000000000000000000000000000", ECHO, OK),
    ("0000000000000000000000000000000000", NOPE, NOTFOUND),
    ("1000000000000000000000000000000000", ECHO, FAIL),
    ("1000000000000000000000000000000000", NOPE, FAIL),
    ("-1", ECHO, FAIL),
    ("-1", NOPE, FAIL),
    ("123abc", ECHO, FAIL),
    ("123abc", NOPE, FAIL),
]


@need_module("eat_post")
@pytest.mark.parametrize(
    "data,uri,expect",
    CASES,
    ids=[f"{c[0] or 'empty'}_{'echo' if c[1] == ECHO else 'nf'}" for c in CASES],
)
def test_contentlength(http, data, uri, expect):
    if expect == FAIL:
        if http.have_min_apache_version("2.2.30") and (
            not http.have_min_apache_version("2.3.0")
            or http.have_min_apache_version("2.4.14")
        ):
            expect = "HTTP/1.1 400 Bad Request"
        else:
            expect = "HTTP/1.1 413 Request Entity Too Large"

    # 'default' in Apache::TestRequest means the main server port.
    sock = http.vhost_socket()
    assert sock

    sock.print(f"POST {uri} HTTP/1.0\r\n")
    sock.print(f"Content-Length: {data}\r\n")
    sock.print("\r\n")
    sock.print("\r\n")

    response = (sock.getline() or "").rstrip()
    assert t_cmp(response, expect), (
        f"response codes POST for {uri} with Content-Length: {data}"
    )
    sock.close()
