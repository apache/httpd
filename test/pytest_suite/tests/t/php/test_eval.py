"""Translated from t/php/eval.t -- need_php; eval()."""

from apache_pytest import need_php


@need_php()
def test_eval(http):
    result = http.GET_BODY("/php/eval.php")
    assert result == 'Hello'
