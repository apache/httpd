r"""Translated from t/security/CVE-2017-7659.t -- mod_http2 NULL deref.

Sends a malformed HTTP/1.0 upgrade-to-h2c request (bogus method "p", broken
Connection/Upgrade/HTTP2-Settings headers). The vulnerability was a NULL-pointer
dereference crashing the child; the test simply asserts the server stayed up and
returned *something* on the socket.

The "h2c" module name has no dedicated vhost in this suite (nor in the Perl one);
vhost_socket("h2c") therefore falls back to the main server port -- matching
Apache::TestRequest's hostport fallback -- so the request hits the main server.

Perl original:
    plan tests => 2, need(need_module('http2'));
    my $module = "h2c";
    Apache::TestRequest::module($module);
    my $sock = Apache::TestRequest::vhost_socket($module);
    ok $sock;
    $sock->print("p * HTTP/1.0\r\nConnection:H/\r\nUpgrade:h2c\r\nHTTP2-Settings:\r\n\r\n");
    ok $sock->getc();   # server didn't crash -> got a byte back
"""

from apache_pytest import need_module


@need_module("http2")
def test_cve_2017_7659(http):
    http.module("h2c")
    sock = http.vhost_socket("h2c")
    assert sock and sock.connected

    sock.print(
        "p * HTTP/1.0\r\n"
        "Connection:H/\r\n"
        "Upgrade:h2c\r\n"
        "HTTP2-Settings:\r\n\r\n"
    )

    # The server should not have crashed -- it should return *something*.
    assert sock.read(), "server returned a response (did not crash)"
    sock.close()
