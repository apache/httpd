r"""Translated from t/security/CVE-2020-1927.t -- mod_rewrite open redirect.

A self-referential RewriteRule plus an encoded CRLF + "http://" in the URI could
be coerced into an open redirect. The fixed server should not match/redirect:
the encoded "%0D%0Ahttp://127.0.0.1/" path against the CVE-2020-1927 Location
(on the merge-disabled vhost) must yield a 404, not a 3xx redirect.

Perl original:
    plan tests => 1, need_min_apache_version('2.4.42');
    my $sock = Apache::TestRequest::vhost_socket("core");
    my $req = "GET /CVE-2020-1927/%0D%0Ahttp://127.0.0.1/ HTTP/1.1\r\n".
              "Host: merge-disabled\r\nConnection: close\r\n\r\n";
    $sock->print($req);
    ... my $response = HTTP::Response->parse($response_data);
    ok t_cmp($response->code, 404, "regex didn't match and redirect");
"""

from apache_pytest import need_min_apache_version, t_cmp


def _status_code(data: str):
    """Parse the HTTP status code from a raw response (None if dropped)."""
    if not data:
        return None
    first = data.split("\n", 1)[0].strip()
    parts = first.split()
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        return int(parts[1])
    return None


@need_min_apache_version("2.4.42")
def test_cve_2020_1927(http):
    http.module("core")
    sock = http.vhost_socket("core")
    assert sock

    req = (
        "GET /CVE-2020-1927/%0D%0Ahttp://127.0.0.1/ HTTP/1.1\r\n"
        "Host: merge-disabled\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    sock.print(req)

    data = sock.read()
    code = _status_code(data)
    assert t_cmp(code, 404), "regex didn't match and redirect"
    sock.close()
