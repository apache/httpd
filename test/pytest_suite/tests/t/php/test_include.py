"""Translated from t/php/include.t -- need_php; include."""

from apache_pytest import need_php


@need_php()
def test_include(http):
    result = http.GET_BODY("/php/include.php")
    assert result == 'Hello'
