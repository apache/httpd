"""Translated from t/php/hello.t -- need_php."""

from apache_pytest import need_php


@need_php()
def test_hello(http):
    result = http.GET_BODY("/php/hello.php")
    assert result == 'Hello World'
