r"""Translated from t/ssl/headers.t.

The /modules/headers/ssl/ .htaccess sets three response headers from mod_ssl
variables via mod_headers' %{VAR}s syntax::

    Header set X-SSL-Flag %{HTTPS}s        -> "on"
    Header set X-SSL-Cert %{SSL_SERVER_CERT}s  -> the unwrapped server cert
    Header set X-SSL-None %{SSL_FOO_BAR}s  -> "(null)" (unknown variable)

If mod_headers doesn't grok the %s tag the request 500s; we skip in that case.
(The Perl test stripped a LWP-specific 'Client-Bad-Header-Line:' artefact from
folded headers -- httpx parses headers itself, so that step is unnecessary.)
"""

import re

import pytest

from apache_pytest import need_module, need_ssl
from apache_pytest.testapi import t_cmp


@need_ssl()
@need_module("headers")
def test_ssl_headers(http):
    http.scheme("https")
    res = http.HEAD("/modules/headers/ssl/")

    if res.status_code == 500:
        pytest.skip("mod_headers doesn't grok %s")

    assert t_cmp(res.headers.get("X-SSL-Flag", ""), re.compile(r"on")), (
        "SSLFlag header set"
    )
    assert t_cmp(
        res.headers.get("X-SSL-Cert", ""), re.compile(r"END CERTIFICATE-----")
    ), "SSL certificate is unwrapped"
    assert t_cmp(
        res.headers.get("X-SSL-None", ""), re.compile(r"\(null\)")
    ), "unknown SSL variable not given"
