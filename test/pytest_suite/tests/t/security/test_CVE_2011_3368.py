r"""Translated from t/security/CVE-2011-3368.t -- proxy request-line injection.

Sends a raw request whose URI is an absolute "@localhost/..." form to the
cve_2011_3368 vhost and asserts the server rejects it with 400 Bad Request
(rather than proxying it). Uses a raw socket because the request line is
deliberately malformed in a way the HTTP client wouldn't emit.

Perl original:
    plan tests => 3, need 'proxy', need_min_apache_version('2.2.5');
    Apache::TestRequest::module("cve_2011_3368");
    my $sock = Apache::TestRequest::vhost_socket();
    ok $sock && $sock->connected;
    $sock->print("GET @localhost/foobar.html HTTP/1.1\r\nHost: ...\r\n\r\n");
    my $line = Apache::TestRequest::getline($sock);
    ok t_cmp($line, qr{^HTTP/1\.. 400 Bad Request}, "got 400 error");
"""

import re

from apache_pytest import need_min_apache_version, need_module, t_cmp


@need_module("proxy")
@need_min_apache_version("2.2.5")
def test_cve_2011_3368(http):
    http.module("cve_2011_3368")
    sock = http.vhost_socket()
    assert sock and sock.connected

    req = (
        "GET @localhost/foobar.html HTTP/1.1\r\n"
        f"Host: {http.hostport()}\r\n"
        "\r\n"
    )
    assert sock.print(req)

    line = sock.getline() or ""
    assert t_cmp(line, re.compile(r"^HTTP/1\.. 400 Bad Request")), "got 400 error"
    sock.close()
