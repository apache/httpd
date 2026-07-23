r"""Translated from t/apache/pr35292.t -- large request body rejected with 413.

Sends a POST to /apache/limits/ declaring a 1 MB body but a small configured
limit, streaming 128 * 8192 bytes. Before the PR 35292 fix the connection would
have been reset before the client finished sending; the fix keeps the socket
alive and returns a 413 response line.

Perl original:
    plan tests => 3, need_min_apache_version('2.1.8');
    my $sock = Apache::TestRequest::vhost_socket('default');
    $sock->print("POST /apache/limits/ HTTP/1.1\r\n");
    $sock->print("Host: localhost\r\n");
    $sock->print("Content-Length: 1048576\r\n\r\n");
    foreach (1..128) { $sock->print('x'x8192) if $sock->connected; }
    ok $sock->connected;
    my $line = Apache::TestRequest::getline($sock) || '';
    ok t_cmp($line, qr{^HTTP/1\.. 413}, "read response-line");
"""

import re

from apache_pytest import need_min_apache_version, t_cmp


@need_min_apache_version("2.1.8")
def test_pr35292(http):
    # 'default' in Apache::TestRequest means the main server port.
    sock = http.vhost_socket()
    assert sock

    sock.print("POST /apache/limits/ HTTP/1.1\r\n")
    sock.print("Host: localhost\r\n")
    sock.print("Content-Length: 1048576\r\n")
    sock.print("\r\n")

    for _ in range(128):
        if sock.connected:
            sock.print("x" * 8192)

    assert sock.connected

    line = sock.getline() or ""
    assert t_cmp(line, re.compile(r"^HTTP/1\.. 413")), "read response-line"
    sock.close()
