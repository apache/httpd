r"""Translated from t/apache/pr17629.t.

The SSI script has DEFLATE applied and includes a CGI (with the CASE filter),
which returns a redirect to a flat file. The test verifies the internal
redirect keeps DEFLATE in the filter chain but loses CASE: the gzipped response
is POSTed back to an inflator and must equal the expected text.

Needs: need_cgi, include, deflate, case_filter.
"""

from apache_pytest import need_cgi, need_module, t_cmp

INFLATOR = "/modules/deflate/echo_post"
URI = "/modules/deflate/ssi/ssi.shtml"
EXPECTED = "begin-foobar-end\n"


@need_cgi()
@need_module("include", "deflate", "case_filter")
def test_pr17629(http):
    content = http.GET_BODY(URI)
    assert t_cmp(content, EXPECTED)

    # raw_response keeps the gzip stream undecoded (httpx would auto-decompress
    # .content) so we can re-POST it through the inflate input filter.
    r = http.raw_response("GET", URI, headers={"Accept-Encoding": "gzip"})
    assert t_cmp(r.status_code, 200)

    renc = r.headers.get("Content-Encoding", "")
    assert t_cmp(renc, "gzip"), "response was gzipped"

    deflated = http.POST_BODY(
        INFLATOR, content=r.raw_content, headers={"Content-Encoding": "gzip"}
    )
    assert t_cmp(deflated, EXPECTED)
