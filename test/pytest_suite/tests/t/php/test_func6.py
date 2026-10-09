"""Translated from t/php/func6.t -- need_php; nested functions."""

from apache_pytest import need_php


@need_php()
def test_func6(http):
    result = http.GET_BODY("/php/func6.php")
    assert result == '4 Hello 4'
