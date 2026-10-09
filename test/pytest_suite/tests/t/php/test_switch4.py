"""Translated from t/php/switch4.t -- need_php."""

from apache_pytest import need_php

EXPECTED = 'zero\none\n2\n3\n4\n5\n6\n7\n8\n9\nzero\none\n2\n3\n4\n5\n6\n7\n8\n9\nzero\none\n2\n3\n4\n5\n6\n7\n8\n9\n'


@need_php()
def test_switch4(http):
    result = http.GET_BODY("/php/switch4.php")
    assert result == EXPECTED
