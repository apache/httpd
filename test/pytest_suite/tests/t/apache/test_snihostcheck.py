r"""Translated from t/apache/snihostcheck.t -- SNI vs Host header checking over TLS.

Against the mod_ssl vhost, sends requests with various Host headers and asserts
the status: an unmatched host stays on the default vhost (200); the "nvh" host
is allowed by the global SNI policy directive (200, or 421 if the suite is run
with NO_TEST_SNIPOLICY set -- not the case here).
"""

import pytest

from apache_pytest import need_ssl, t_cmp

# (host header, expected code, description) -- NO_TEST_SNIPOLICY not set here.
CASES = [
    ("unmatched", 200, "no hop, stays on default vhost"),
    ("nvh", 200, "hop allowed by global directive"),
]


@need_ssl()
@pytest.mark.parametrize(("host", "expect", "desc"), CASES, ids=lambda v: str(v))
def test_snihostcheck(http, host, expect, desc):
    http.scheme("https")
    r = http.GET("/", headers={"Host": host})
    assert t_cmp(r.status_code, expect), desc
