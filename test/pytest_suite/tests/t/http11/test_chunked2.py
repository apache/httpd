"""Translated from t/http11/chunked2.t -- ap_http_chunk_filter regression.

Perl original (plan tests => 2, need 'bucketeer'):
    Apache::TestRequest::user_agent(keep_alive => 1);
    my $r = GET("/apache/chunked/flush.html");
    ok t_cmp($r->code, 200, "successful response");
    ok t_cmp($r->content, "aaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbb");

Requires the bucketeer C test module.
"""

from apache_pytest import need_module, t_cmp


@need_module("bucketeer")
def test_chunked_flush(http):
    r = http.GET("/apache/chunked/flush.html")
    assert t_cmp(r.status_code, 200), "successful response"
    assert t_cmp(r.text, "aaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbb")
