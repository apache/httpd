r"""Translated from t/security/CVE-2011-3368-rewrite.t -- rewrite proxy injection.

Like CVE-2011-3368 but targets the cve_2011_3368_rewrite vhost (mod_rewrite
proxying). Sends a request line with an absolute "@localhost/..." URI and
asserts a 400 Bad Request rather than the server proxying it.

Perl original:
    plan tests => 3, need 'rewrite';
    Apache::TestRequest::module("cve_2011_3368_rewrite");
    my $sock = Apache::TestRequest::vhost_socket();
    ok $sock && $sock->connected;
    my $req = "GET @"."localhost/foobar.html HTTP/1.1\r\nHost: ...\r\n\r\n";
    ok $sock->print($req);
    my $line = Apache::TestRequest::getline($sock) || '';
    ok t_cmp($line, qr{^HTTP/1\.. 400 Bad Request}, "got 400 error");
"""

import re

from apache_pytest import need_module, t_cmp


@need_module("rewrite")
def test_cve_2011_3368_rewrite(http):
    http.module("cve_2011_3368_rewrite")
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
