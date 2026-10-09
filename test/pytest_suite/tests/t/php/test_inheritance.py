"""Translated from t/php/inheritance.t -- need_php."""

from apache_pytest import need_php

EXPECTED = 'This is class foo\na = 2\nb = 5\n10\n-----\nThis is class bar\na = 4\nb = 3\nc = 12\n12\n'


@need_php()
def test_inheritance(http):
    result = http.GET_BODY("/php/inheritance.php")
    assert result == EXPECTED
