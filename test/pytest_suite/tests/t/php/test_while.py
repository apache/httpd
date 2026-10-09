"""Translated from t/php/while.t -- need_php."""

from apache_pytest import need_php


@need_php()
def test_while(http):
    result = http.GET_BODY("/php/while.php")
    assert result == '123456789'
