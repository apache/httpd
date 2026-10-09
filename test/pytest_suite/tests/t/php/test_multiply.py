"""Translated from t/php/multiply.t -- need_php; 2*4*8=64."""

from apache_pytest import need_php


@need_php()
def test_multiply(http):
    result = http.GET_BODY("/php/multiply.php")
    assert result == '64'
