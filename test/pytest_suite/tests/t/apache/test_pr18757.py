r"""Translated from t/apache/pr18757.t -- proxy strips Content-Length on HEAD.

Regression test for PR 18757. First a plain GET confirms the resource and its
Content-Length. Then a raw HEAD request is sent through the forward proxy
(mod_proxy vhost, ProxyRequests On) using an absolute URL, and we assert that
the proxied HEAD response still carries the correct Content-Length header
(i.e. the proxy did not strip it). Uses a raw socket because LWP misreports the
response headers for HEAD.

Perl original:
    plan tests => 3, need 'proxy', need_min_apache_version('2.2.1'), need_cgi;
    Apache::TestRequest::module("mod_proxy");
    my $r = GET("/index.html");
    ok t_cmp($r->code, 200, "200 response from GET");
    my $clength = $r->content_length;
    my $url = Apache::TestRequest::resolve_url("/index.html");
    my $hostport = Apache::TestRequest::hostport();
    my $sock = Apache::TestRequest::vhost_socket("mod_proxy");
    $sock->print("HEAD $url HTTP/1.1\r\nHost: $hostport\r\n\r\n");
    ... ok whether a "Content-Length: $clength" header is present.
"""

import re

from apache_pytest import need_cgi, need_min_apache_version, need_module, t_cmp


@need_module("proxy")
@need_min_apache_version("2.2.1")
@need_cgi()
def test_pr18757(http):
    http.module("mod_proxy")

    r = http.GET("/index.html")
    assert t_cmp(r.status_code, 200), "200 response from GET"

    clength = r.headers.get("Content-Length")
    assert clength is not None, "GET returned a Content-Length"

    hostport = http.hostport()
    url = f"http://{hostport}/index.html"

    sock = http.vhost_socket("mod_proxy")
    assert sock

    sock.print(f"HEAD {url} HTTP/1.1\r\n")
    sock.print(f"Host: {hostport}\r\n")
    sock.print("\r\n")

    found = False
    while True:
        response = (sock.getline() or "").rstrip()
        if re.search(rf"Content-Length: {re.escape(clength)}", response):
            found = True
        if response == "":
            break

    assert found, "whether proxy strips Content-Length header"
    sock.close()
