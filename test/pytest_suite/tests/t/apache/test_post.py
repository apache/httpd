"""Translated from t/apache/post.t -- run_post_test('eat_post').

POSTs `length` bytes of 'a' to /eat_post for a matrix of sizes; the eat_post C
module consumes the body and echoes back the byte count, which must equal the
posted length.
"""

import pytest

from apache_pytest import need_module, t_cmp

# run_post_test small sizes: 1k..9k, 10k..50k, 100k (POST_HUGE adds more; off here).
SIZES = [*range(1, 10), *range(10, 51), 100]


@need_module("eat_post")
@pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s}k")
def test_post(http, size):
    length = size * 1024
    body = http.POST_BODY("/eat_post", content=b"a" * length)
    assert t_cmp(length, body.strip()), "length posted"
