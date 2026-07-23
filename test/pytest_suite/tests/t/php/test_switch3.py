"""Translated from t/php/switch3.t -- need_php."""

from apache_pytest import need_php

EXPECTED = 'i=0\nIn branch 0\ni=1\nIn branch 1\ni=2\nIn branch 2\ni=3\nIn branch 3\nhi\n'


@need_php()
def test_switch3(http):
    result = http.GET_BODY("/php/switch3.php")
    assert result == EXPECTED
