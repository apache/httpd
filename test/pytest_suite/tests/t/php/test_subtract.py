"""Translated from t/php/subtract.t -- need_php; 27-7-10=10."""

from apache_pytest import need_php


@need_php()
def test_subtract(http):
    result = http.GET_BODY("/php/subtract.php")
    assert result == '10'
