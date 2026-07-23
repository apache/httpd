"""Translated from t/apache/rwrite.t -- Apache::TestCommon::run_write_test('test_rwrite').

The test_rwrite C module writes `length` bytes when asked via
GET /test_rwrite?<buff_size>,<length>; the test verifies the received body
length matches for a matrix of body sizes and internal buffer sizes.
"""

import pytest

from apache_pytest import need_module, t_cmp

# 1k..9k, 10k..50k, 100k, 300k, 500k, 2Mb, 4Mb, 6Mb, 10Mb (run_write_test sizes)
SIZES = [*range(1, 10), *range(10, 51), 100, 300, 500, 2000, 4000, 6000, 10_000]
BUFF_SIZES = [1024, 8192]

CASES = [(b, s) for b in BUFF_SIZES for s in SIZES]


@need_module("test_rwrite")
@pytest.mark.parametrize(("buff_size", "size"), CASES, ids=lambda v: str(v))
def test_rwrite(http, buff_size, size):
    length = size * 1024
    r = http.GET(f"/test_rwrite?{buff_size},{length}")
    assert t_cmp(len(r.content), length), "bytes in body"
