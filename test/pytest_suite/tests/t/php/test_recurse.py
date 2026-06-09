"""Translated from t/php/recurse.t -- need_php."""

from apache_pytest import need_php


@need_php()
def test_recurse(http):
    result = http.GET_BODY("/php/recurse.php")
    assert result == '1 2 3 4 5 6 7 8 9 \n'
