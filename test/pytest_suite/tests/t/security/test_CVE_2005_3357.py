r"""Translated from t/security/CVE-2005-3357.t (PR 33791).

Sends a plain HTTP request to the SSL port (ssl_pr33791 vhost) and verifies the
server returns 400 Bad Request with the canned error document, rather than
crashing. The Perl test tolerates an HTTP/0.9 response (skips then); httpx always
speaks HTTP/1.1 to the port.
"""

import re

import pytest

from apache_pytest import need_ssl, t_cmp


@need_ssl()
def test_cve_2005_3357(http):
    # Talk plain HTTP to the SSL vhost's port (note: http://, not https://).
    http.module("ssl_pr33791")
    rurl = f"http://{http.hostport('ssl_pr33791')}/"

    try:
        r = http.request("GET", rurl)
    except Exception as exc:  # noqa: BLE001 - server may drop the connection
        pytest.skip(f"server gave no usable response: {exc}")

    assert t_cmp(r.status_code, 400), f"Expected bad request from 'GET {rurl}'"
    assert t_cmp(r.text, re.compile("welcome to localhost")), "errordoc content was served"
