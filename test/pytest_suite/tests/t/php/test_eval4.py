"""Translated from t/php/eval4.t -- need_php; eval()."""

from apache_pytest import need_php

EXPECTED = "hey, this is a regular echo'd eval()\nhey, this is a function inside an eval()!\nhey, this is a regular echo'd eval()\nhey, this is a function inside an eval()!\nhey, this is a regular echo'd eval()\nhey, this is a function inside an eval()!\nhey, this is a regular echo'd eval()\nhey, this is a function inside an eval()!\nhey, this is a regular echo'd eval()\nhey, this is a function inside an eval()!\nhey, this is a regular echo'd eval()\nhey, this is a function inside an eval()!\nhey, this is a regular echo'd eval()\nhey, this is a function inside an eval()!\nhey, this is a regular echo'd eval()\nhey, this is a function inside an eval()!\nhey, this is a regular echo'd eval()\nhey, this is a function inside an eval()!\nhey, this is a regular echo'd eval()\nhey, this is a function inside an eval()!\n"


@need_php()
def test_eval4(http):
    result = http.GET_BODY("/php/eval4.php")
    assert result == EXPECTED
