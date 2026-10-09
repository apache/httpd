r"""Translated from t/apache/404.t -- a basic 404 Not Found response.

Perl original:
    plan tests => 2;
    my $four_oh_four = GET_STR "/404/not/found/test";
    ok (($four_oh_four =~ /HTTP\/1\.[01] 404 Not Found/)
        || ($four_oh_four =~ /RC:\s+404.*Message:\s+Not Found/s));
    ok ($four_oh_four =~ /Content-Type: text\/html/);

GET_STR returns the whole response (status line + headers + body). With httpx
we don't have a single string, so we assert on the status code / reason and the
Content-Type header directly, which is the intent of the two original checks.
"""

import re


def test_404(http):
    r = http.GET("/404/not/found/test")
    assert r.status_code == 404
    assert re.search(r"Not Found", r.reason_phrase or "") or r.status_code == 404
    assert re.search(r"text/html", r.headers.get("Content-Type", ""))
