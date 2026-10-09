"""Translated from t/php/getenv.t -- need_php.

Regression test for http://bugs.php.net/bug.php?id=19840 -- getenv(REQUEST_METHOD)
should return "GET".
"""

from apache_pytest import need_php, t_cmp


@need_php()
def test_getenv(http):
    assert t_cmp(http.GET_BODY("/php/getenv.php"), "GET"), "getenv(REQUEST_METHOD)"
