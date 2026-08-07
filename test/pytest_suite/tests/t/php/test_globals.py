"""Translated from t/php/globals.t -- need_php."""

from apache_pytest import need_php


@need_php()
def test_globals(http):
    result = http.GET_BODY("/php/globals.php")
    assert result == '1 5 2 2 10 5  2 5 3 2 10 5  3 5 4 2 \n'
