"""Translated from t/php/nestif.t -- need_php."""

from apache_pytest import need_php


@need_php()
def test_nestif(http):
    result = http.GET_BODY("/php/nestif.php")
    assert result == 'good\n'
