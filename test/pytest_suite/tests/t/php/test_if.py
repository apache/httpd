"""Translated from t/php/if.t -- need_php."""

from apache_pytest import need_php


@need_php()
def test_if(http):
    result = http.GET_BODY("/php/if.php")
    assert result == 'Yes'
