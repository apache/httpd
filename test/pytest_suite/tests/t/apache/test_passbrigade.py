"""Translated from t/apache/passbrigade.t -- run_write_test('test_pass_brigade').

Same size matrix as rwrite, against the test_pass_brigade C module which streams
`length` bytes via ap_pass_brigade; verify the received body length matches.
"""

import pytest

from apache_pytest import need_module, t_cmp

SIZES = [*range(1, 10), *range(10, 51), 100, 300, 500, 2000, 4000, 6000, 10_000]
BUFF_SIZES = [1024, 8192]
CASES = [(b, s) for b in BUFF_SIZES for s in SIZES]


@need_module("test_pass_brigade")
@pytest.mark.parametrize(("buff_size", "size"), CASES, ids=lambda v: str(v))
def test_pass_brigade(http, buff_size, size):
    length = size * 1024
    r = http.GET(f"/test_pass_brigade?{buff_size},{length}")
    assert t_cmp(len(r.content), length), "bytes in body"
