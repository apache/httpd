"""Translated from t/php/do-while.t -- need_php."""

from apache_pytest import need_php


@need_php()
def test_do_while(http):
    result = http.GET_BODY("/php/do-while.php")
    assert result == '321'
