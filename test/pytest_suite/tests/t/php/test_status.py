"""Translated from t/php/status.t -- need_php.

Regression test for http://bugs.php.net/bug.php?id=31519 -- status.php sets the
HTTP response code from the ?code= parameter.
"""

import pytest

from apache_pytest import need_php, t_cmp

CODES = [404, 599]


@need_php()
@pytest.mark.parametrize("code", CODES)
def test_status(http, code):
    assert t_cmp(http.GET_RC(f"/php/status.php?code={code}"), code), (
        "regression test for http://bugs.php.net/bug.php?id=31519"
    )
