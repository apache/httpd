r"""Translated from t/apache/pr37166.t -- regression test for PR 37166.

A CGI script that outputs an explicit "Status: 200" must not be subject to
conditional request processing (an If-Modified-Since must still get the body).

Needs: need_cgi.
"""

from apache_pytest import need_cgi, t_cmp

URI = "/modules/cgi/pr37166.pl"


@need_cgi()
def test_pr37166(http):
    r = http.GET(URI)
    assert t_cmp(r.status_code, 200), "SSI was allowed for location"
    assert t_cmp(r.text, "Hello world\n"), "file was served with correct content"

    r = http.GET(URI, headers={"If-Modified-Since": "Tue, 15 Feb 2005 15:00:00 GMT"})
    assert t_cmp(r.status_code, 200), "explicit 200 response"
    assert t_cmp(r.text, "Hello world\n"), (
        "file was again served with correct content"
    )
