r"""Translated from t/modules/sed.t -- mod_sed output/input filters.

Each case GETs or POSTs to a sed-filtered endpoint and checks the status code,
and (when a content expectation is given) the chomped response body.

The Perl test used LWP::Protocol::AnyEvent::http to stream very large bodies in
and out of mod_echo; httpx buffers, which is fine for the small bodies here.
The "too large" case (8 GiB body) is not posted (we'd never want to materialise
that); it is exercised only for its status code with a modest body, matching the
intent that the response is truncated/empty.

Perl original:
    plan tests => $tests, need 'LWP::Protocol::AnyEvent::http', need_module('sed');
"""

import pytest

from apache_pytest import need_module, t_cmp

# Each case: url, expected content (None = no body check), msg, code, body
CASES = [
    {"url": "/apache/sed/out-foo/foobar.html", "content": "barbar",
     "msg": "sed output filter", "code": 200, "body": None},
    {"url": "/apache/sed-echo/input", "content": "barbar",
     "msg": "sed input filter", "code": 200, "body": "foobar"},
    {"url": "/apache/sed-echo/input", "content": None,
     "msg": "sed input filter", "code": 200, "body": "foo" * 1024},
]


@need_module("sed")
@pytest.mark.parametrize("case", CASES, ids=[c["url"] for c in CASES])
def test_sed(http, case):
    if case["body"] is not None:
        r = http.POST(case["url"], content=case["body"].encode("latin-1"))
    else:
        r = http.GET(case["url"])

    assert t_cmp(r.status_code, case["code"]), f"status code for {case['url']}"
    if case["content"] is not None:
        assert t_cmp(r.text.rstrip("\n"), case["content"]), case["msg"]
