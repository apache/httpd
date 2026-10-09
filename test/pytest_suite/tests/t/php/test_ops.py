"""Translated from t/php/ops.t -- need_php; 8|4&8=8."""

from apache_pytest import need_php


@need_php()
def test_ops(http):
    result = http.GET_BODY("/php/ops.php")
    assert result == '8'
