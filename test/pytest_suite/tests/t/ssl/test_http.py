r"""Translated from t/ssl/http.t.

Verify we can send a non-SSL (plain HTTP) request to the SSL port without the
server dumping core: mod_ssl should answer with a 400 and an error document
containing the hint "speaking plain HTTP to an SSL-enabled server port".

The Perl test built ``http://$hostport$url`` from the ssl vhost's host:port and
set APACHE_TEST_HTTP_09_OK so LWP wouldn't croak on an HTTP/0.9 response.
"""

import re

from apache_pytest import need_ssl


@need_ssl()
def test_plain_http_to_ssl_port(http):
    ssl_name = http.vars("ssl_module_name") or "mod_ssl"
    port = http.vhost_port(ssl_name)
    servername = http.servername
    url = f"http://{servername}:{port}/index.html"

    res = http.GET(url)

    proto = res.http_version  # e.g. "HTTP/1.1"
    if proto == "HTTP/0.9":
        import pytest

        pytest.skip("server gave HTTP/0.9 response")

    assert res.status_code == 400, f"Expected bad request from 'GET {url}'"
    assert re.search(
        r"speaking plain HTTP to an SSL-enabled server port", res.text
    ), "that error document contains the proper hint"
