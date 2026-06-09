"""Translated from t/modules/buffer.t -- mod_buffer (with mod_reflector).

POST a small body and a big body (~300KB, over the default BufferSize) to each
buffer location and assert the reflector echoes the body back unchanged.

Perl original used ``need 'mod_reflector', 'mod_buffer'``.
"""

import pytest

from apache_pytest import need_module, t_cmp

TESTCASES = [
    ("/apache/buffer_in/", "foo"),
    ("/apache/buffer_out/", "foo"),
    ("/apache/buffer_in_out/", "foo"),
]

BIGSIZE = 100000


@need_module("mod_reflector", "mod_buffer")
@pytest.mark.parametrize("url,payload", TESTCASES, ids=lambda v: str(v))
def test_buffer(http, url, payload):
    # Small query.
    r = http.POST(url, content=payload)
    assert t_cmp(r.status_code, 200), "Checking return code is '200'"
    assert t_cmp(r.text, payload)

    # Big query (~300KB, over the default BufferSize).
    big = payload * BIGSIZE
    r = http.POST(url, content=big)
    assert t_cmp(r.status_code, 200), "Checking return code is '200'"
    assert t_cmp(r.text, big)
