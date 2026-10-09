"""Translated from t/http11/clength.t -- Content-Length with FLUSH buckets.

Perl original (plan tests => 3*keys, need 'bucketeer'):
    foreach my $path (sort keys %tests) {
        my $r = GET($path);
        ok t_cmp($r->code, 200, "successful response");
        ok t_cmp($r->header("Content-Length"), length $expected);
        ok t_cmp($r->content, $expected);
    }

Requires the bucketeer C test module.
"""

import pytest

from apache_pytest import need_module, t_cmp

# flushheap0 inserts a single FLUSH bucket after the content, before EOS
TESTS = {
    "/foobar.html": "foobar",
    "/apache/chunked/flushheap0.html": "bbbbbbbbbb",
}


@need_module("bucketeer")
@pytest.mark.parametrize("path", sorted(TESTS), ids=lambda p: p)
def test_clength(http, path):
    expected = TESTS[path]
    r = http.GET(path)
    assert t_cmp(r.status_code, 200), "successful response"
    assert t_cmp(r.headers.get("Content-Length"), len(expected))
    assert t_cmp(r.text, expected)
