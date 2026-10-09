r"""Translated from t/modules/ratelimit.t -- mod_ratelimit.

Each case GETs a rate-limited URL and asserts the response code is 200 -- the
rate limiting throttles the transfer but the request still succeeds. The Perl
test wrapped GET in eval to tolerate a dubious status line from a slow/aborted
transfer; here a short client timeout plays that role and any transport error
is surfaced as a non-200 failure.

Perl original:
    plan tests => scalar @testcases, need need_lwp,
        need_module('mod_ratelimit'), need_module('mod_autoindex'),
        need_min_apache_version('2.4.35');
"""

import pytest

from apache_pytest import need_min_apache_version, need_module, t_cmp

CASES = [
    ("/apache/ratelimit/", 200, "ratelimited small file"),
    ("/apache/ratelimit/autoindex/", 200, "ratelimited small autoindex output"),
    ("/apache/ratelimit/chunk?0,8192", 200, "ratelimited chunked response"),
]


@need_module("ratelimit", "autoindex")
@need_min_apache_version("2.4.35")
@pytest.mark.parametrize("url,code,desc", CASES, ids=[c[2] for c in CASES])
def test_ratelimit(http, url, code, desc):
    r = http.GET(url)
    assert t_cmp(r.status_code, code), desc
