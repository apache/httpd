"""Translated from t/php/func1.t -- need_php; strlen("abcdef")."""

from apache_pytest import need_php


@need_php()
def test_func1(http):
    result = http.GET_BODY("/php/func1.php")
    assert result == '6'
