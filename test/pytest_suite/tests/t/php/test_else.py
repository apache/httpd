"""Translated from t/php/else.t -- need_php."""

from apache_pytest import need_php


@need_php()
def test_else(http):
    result = http.GET_BODY("/php/else.php")
    assert result == 'good\n'
