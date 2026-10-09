r"""Translated from t/apache/errordoc.t -- ErrorDocument directive behavior.

Exercises per-server, inherited, redefined, restored and merged ErrorDocument
settings, plus a TRACE-not-allowed (405) case. Requests are made against the
``error_document`` vhost.

Needs: need_lwp.
"""

import re

from apache_pytest import need_lwp, t_cmp


@need_lwp()
def test_errordoc(http):
    http.module("error_document")

    # basic ErrorDocument tests
    r = http.GET("/notfound.html")
    assert t_cmp(r.status_code, 404), "notfound.html code"
    assert t_cmp(r.text.rstrip("\n"), re.compile("per-server 404")), (
        "notfound.html content"
    )

    r = http.GET("/inherit/notfound.html")
    assert t_cmp(r.status_code, 404), "/inherit/notfound.html code"
    assert t_cmp(r.text.rstrip("\n"), re.compile("per-server 404")), (
        "/inherit/notfound.html content"
    )

    r = http.GET("/redefine/notfound.html")
    assert t_cmp(r.status_code, 404), "/redefine/notfound.html code"
    assert t_cmp(r.text.rstrip("\n"), "per-dir 404"), (
        "/redefine/notfound.html content"
    )

    r = http.GET("/restore/notfound.html")
    content = r.text.rstrip("\n")
    assert t_cmp(r.status_code, 404), "/restore/notfound.html code"
    if http.have_min_apache_version("2.0.51"):
        expected = re.compile("Not Found")
    elif http.have_apache(2):
        expected = "default"
    else:
        expected = re.compile("Additionally, a 500")
    assert t_cmp(content, expected), "/restore/notfound.html content"

    r = http.GET("/apache/notfound.html")
    assert t_cmp(r.status_code, 404), "/merge/notfound.html code"
    assert t_cmp(r.text.rstrip("\n"), "testing merge"), "/merge/notfound.html content"

    r = http.GET("/apache/etag/notfound.html")
    assert t_cmp(r.status_code, 404), "/merge/merge2/notfound.html code"
    assert t_cmp(r.text.rstrip("\n"), "testing merge"), (
        "/merge/merge2/notfound.html content"
    )

    r = http.GET("/bounce/notfound.html")
    assert t_cmp(r.status_code, 404), "/bounce/notfound.html code"
    assert t_cmp(r.text.rstrip("\n"), re.compile("expire test")), (
        "/bounce/notfound.html content"
    )

    # TRACE not allowed
    url = http.vhost_url("error_document", "/trace/notallowed.html")
    r = http.request("TRACE", url)
    content = r.text.rstrip("\n")
    assert t_cmp(r.status_code, 405), "/trace/notallowed.html code"
    if http.have_min_apache_version("2.5.1"):
        assert t_cmp(
            content,
            re.compile("The requested method TRACE is not allowed for this URL."),
        ), "/trace/notallowed.html content"
        assert t_cmp(content, re.compile("Additionally, a 404 Not Found")), (
            "/trace/notallowed.html content"
        )
