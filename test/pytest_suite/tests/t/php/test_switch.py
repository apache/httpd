"""Translated from t/php/switch.t -- need_php."""

from apache_pytest import need_php


@need_php()
def test_switch(http):
    result = http.GET_BODY("/php/switch.php")
    assert result == 'good\n'
