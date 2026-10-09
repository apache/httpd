"""Translated from t/http11/post.t -- run_post_test('eat_post') over HTTP/1.1.

Same as t/apache/post but with keep-alive enabled (HTTP/1.1). httpx uses
HTTP/1.1 with persistent connections by default, so this exercises the
keep-alive path. The eat_post module echoes the consumed byte count.
"""

import pytest

from apache_pytest import need_module, t_cmp

SIZES = [*range(1, 10), *range(10, 51), 100]


@need_module("eat_post")
@pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s}k")
def test_post_http11(http, size):
    length = size * 1024
    body = http.POST_BODY("/eat_post", content=b"a" * length)
    assert t_cmp(length, body.strip()), "length posted"
