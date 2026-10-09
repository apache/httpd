r"""Translated from t/security/CVE-2009-1890.t -- mod_proxy reverse body DoS.

Sends a POST through the reverse proxy (proxy_http_reverse vhost) to an echoing
CGI, with a deliberately malformed "Content-Length: 0100000" header, streaming
the 100000-byte body in two halves with a pause between. The vulnerability hung
the server; the fixed server must parse the request, return 200, and echo the
entire body back.

Perl original:
    plan tests => 7, need [qw(mod_proxy proxy_http.c)];
    my $len = 100000;
    my $sock = Apache::TestRequest::vhost_socket('proxy_http_reverse');
    ok $sock && $sock->connected;
    my $req = "POST /reverse/modules/cgi/perl_echo.pl HTTP/1.0\r\n".
              "Content-Length: 0".$len."\r\n\r\n";
    ok $sock->print($req);
    my $half_body = 'x' x ($len/2);
    ok $sock->print($half_body); sleep(1); ok $sock->print($half_body);
    ... ok readable; ok status =~ ^HTTP/1.. 200; read body; ok $len == 0.
"""

import re
import time

from apache_pytest import need_cgi, need_module, t_cmp


@need_module("proxy", "proxy_http.c")
@need_cgi()
def test_cve_2009_1890(http):
    length = 100000

    sock = http.vhost_socket("proxy_http_reverse")
    assert sock and sock.connected

    req = (
        "POST /reverse/modules/cgi/perl_echo.pl HTTP/1.0\r\n"
        f"Content-Length: 0{length}\r\n"
        "\r\n"
    )
    assert sock.print(req)

    half_body = "x" * (length // 2)
    assert sock.print(half_body)
    time.sleep(1)
    assert sock.print(half_body)

    # Status line.
    line = sock.getline() or ""
    assert t_cmp(line, re.compile(r"^HTTP/1\.. 200")), "request was parsed"

    # Drain headers up to the blank line.
    while True:
        line = sock.getline() or ""
        line = line.strip("\r\n")
        if line == "":
            break

    # Drain the body and confirm we read the whole thing back.
    body = sock.read()
    remaining = length - len(body)
    assert t_cmp(remaining, 0), "read entire body"
    sock.close()
