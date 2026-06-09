"""Translated from t/php/umask.t -- need_php4.

Verifies umask() is reset after each script execution: the first request's
value is captured, then four further requests must all return the same value.
"""

from apache_pytest import need_php, t_cmp


@need_php()
def test_umask(http):
    first = http.GET_BODY("/php/umask.php")
    for n in range(1, 5):
        attempt = http.GET_BODY("/php/umask.php")
        assert t_cmp(attempt, first), f"umask was {attempt} not {first} for request {n}"
