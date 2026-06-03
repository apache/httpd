"""Translated from t/php/divide.t -- need_php; 27/3/3=3."""

from apache_pytest import need_php


@need_php()
def test_divide(http):
    result = http.GET_BODY("/php/divide.php")
    assert result == '3'
