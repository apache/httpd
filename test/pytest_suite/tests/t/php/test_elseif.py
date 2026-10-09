"""Translated from t/php/elseif.t -- need_php."""

from apache_pytest import need_php


@need_php()
def test_elseif(http):
    result = http.GET_BODY("/php/elseif.php")
    assert result == 'good\n'
