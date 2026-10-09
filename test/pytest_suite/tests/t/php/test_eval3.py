"""Translated from t/php/eval3.t -- need_php; eval()."""

from apache_pytest import need_php

EXPECTED = 'hey\n0\nhey\n1\nhey\n2\nhey\n3\nhey\n4\nhey\n5\nhey\n6\nhey\n7\nhey\n8\nhey\n9\n'


@need_php()
def test_eval3(http):
    result = http.GET_BODY("/php/eval3.php")
    assert result == EXPECTED
