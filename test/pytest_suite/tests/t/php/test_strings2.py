"""Translated from t/php/strings2.t -- need_php."""

from apache_pytest import need_php

EXPECTED = 'Testing strtok: passed\nTesting strstr: passed\nTesting strrchr: passed\nTesting strtoupper: passed\nTesting strtolower: passed\nTesting substr: passed\nTesting rawurlencode: passed\nTesting rawurldecode: passed\nTesting urlencode: passed\nTesting urldecode: passed\nTesting quotemeta: passed\nTesting ufirst: passed\nTesting strtr: passed\nTesting addslashes: passed\nTesting stripslashes: passed\nTesting uniqid: passed\n'


@need_php()
def test_strings2(http):
    result = http.GET_BODY("/php/strings2.php")
    assert result == EXPECTED
