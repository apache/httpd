"""Translated from t/php/add.t -- need_php; 1+2+3=6."""

from apache_pytest import need_php


@need_php()
def test_add(http):
    result = http.GET_BODY("/php/add.php")
    assert result == '6'
