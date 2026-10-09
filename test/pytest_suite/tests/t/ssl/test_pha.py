r"""Translated from t/ssl/pha.t -- TLSv1.3 Post-Handshake Authentication.

The TLSv1.3 equivalent of pr12355.t. With PHA enabled on the client SSL context
(client.py sets ctx.post_handshake_auth=True), httpx performs real TLS 1.3 PHA:

* GET /verify/ with no client cert -> 403 (cert required, none presented).
* POST 101 bytes to /require/small (SSLRenegBufferSize 10) with a client cert ->
  413, because the buffered request body exceeds the reneg/PHA buffer limit.
* POST 10000 bytes to /verify/ with a client cert -> 200 and the response echoes
  the request body (perl_echo.pl).

Requires httpd >= 2.4.47 and a CGI module (perl_echo.pl).
"""

import pytest

from apache_pytest import need_cgi, need_min_apache_version, need_ssl, t_cmp


@need_ssl()
@need_cgi()
@need_min_apache_version("2.4.47")
def test_pha(http):
    http.scheme("https")

    # TLS 1.3 must actually be negotiated for this to be a PHA test.
    if not http.GET("/").is_success:
        pytest.skip("TLSv1.3 not supported")

    r = http.GET("/verify/", cert=None)
    assert t_cmp(r.status_code, 403), "access must be denied without client certificate"

    # SSLRenegBufferSize 10 on /require/small -> a 101-byte body must 413.
    r = http.POST("/require/small/perl_echo.pl", content=b"y" * 101, cert="client_ok")
    assert t_cmp(r.status_code, 413), "PHA reneg body buffer size restriction works"

    # A large POST to /verify/ succeeds and echoes the body back.
    body = b"x" * 10000
    r = http.POST("/verify/modules/cgi/perl_echo.pl", content=body, cert="client_ok")
    assert t_cmp(r.status_code, 200), "PHA works with POST body"
    assert t_cmp(r.content, body), "request body matches response"
