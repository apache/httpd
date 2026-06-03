r"""Translated from t/security/CVE-2004-0942.t -- folded-header overflow -> 400.

CAN-2004-0942 was a memory leak in <=2.0.52 handling of whitespace in folded
headers. This sends a folded "Hello:" header whose accumulated whitespace
exceeds the field-length limit and asserts a 400 response.

Perl original:
    plan tests => 2, need_min_apache_version('2.0');
    my $sock = Apache::TestRequest::vhost_socket('default');
    $sock->print("GET /index.html HTTP/1.0\r\n");
    $sock->print("Hello:\r\n");
    foreach (1..100) { $sock->print(" "x500 . "\r\n") if $sock->connected; }
    $sock->print("\r\n") if $sock->connected;
    my $line = Apache::TestRequest::getline($sock) || '';
    ok t_cmp($line, qr{^HTTP/1\.. 400}, "request was refused");
"""

import re

from apache_pytest import need_min_apache_version, t_cmp


@need_min_apache_version("2.0")
def test_cve_2004_0942(http):
    # 'default' in Apache::TestRequest means the main server port.
    sock = http.vhost_socket()
    assert sock

    sock.print("GET /index.html HTTP/1.0\r\n")
    sock.print("Hello:\r\n")
    for _ in range(100):
        if sock.connected:
            sock.print(" " * 500 + "\r\n")
    if sock.connected:
        sock.print("\r\n")

    line = sock.getline() or ""
    assert t_cmp(line, re.compile(r"^HTTP/1\.. 400")), "request was refused"
    sock.close()
