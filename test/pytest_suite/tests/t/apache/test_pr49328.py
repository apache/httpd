r"""Translated from t/apache/pr49328.t.

GET an SSI page with DEFLATE requested, POST the gzipped result back to an
inflator and verify the round-tripped content.

Needs: filter, include, deflate.
"""

from apache_pytest import need_module, t_cmp

INFLATOR = "/modules/deflate/echo_post"
URI = "/modules/filter/pr49328/pr49328.shtml"


@need_module("filter", "include", "deflate")
def test_pr49328(http):
    # GET_RAW: keep the gzip stream undecoded so we can re-POST it through the
    # inflate input filter (httpx would otherwise auto-decompress .content).
    content = http.GET_RAW(URI, headers={"Accept-Encoding": "gzip"})
    deflated = http.POST_BODY(
        INFLATOR, content=content, headers={"Content-Encoding": "gzip"}
    )
    assert t_cmp(deflated, "before\nincluded\nafter\n")
