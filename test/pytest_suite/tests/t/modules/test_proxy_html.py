r"""Translated from t/modules/proxy_html.t -- mod_proxy_html link/meta rewriting.

mod_proxy_html is not built locally, so these SKIP via @need_module. When the
module is present, each case GETs an HTML page proxied through mod_proxy_html
and checks the status plus one of: content + content-type, an extracted meta
header (metafix), a rewritten-URL regex, or a stripped/kept comment regex.

Perl original: plan tests => $total_tests, need [qw(proxy_html proxy)];
"""

import re

import pytest

from apache_pytest import need_module, t_cmp

# Unified test array (faithful to the Perl @tests).
TESTS = [
    # Basic content tests
    {"type": "content", "path": "equiv.html", "content_type": r"text/html.*",
     "content": r'<meta content="X" http-equiv="999">', "desc": "fetching equiv.html"},
    # Meta tag extraction tests (metafix())
    {"type": "meta", "path": "meta_simple.html", "header": "X-Custom-Header",
     "value": "SimpleValue", "desc": "simple meta tag"},
    {"type": "meta", "path": "meta_quotes.html", "header": "X-Double-Quote",
     "value": "Value with double quotes", "desc": "double quotes"},
    {"type": "meta", "path": "meta_quotes.html", "header": "X-Single-Quote",
     "value": "Value with single quotes", "desc": "single quotes"},
    {"type": "meta", "path": "meta_quotes.html", "header": "X-No-Quote",
     "value": "ValueNoQuotes", "desc": "no quotes"},
    {"type": "meta", "path": "meta_whitespace.html", "header": "X-Extra-Space",
     "value": "Value with spaces", "desc": "extra whitespace"},
    {"type": "meta", "path": "meta_whitespace.html", "header": "X-Tabs",
     "value": "Tabs and spaces", "desc": "tabs and spaces"},
    {"type": "meta", "path": "meta_multiple.html", "header": "X-First",
     "value": "First", "desc": "first of multiple"},
    {"type": "meta", "path": "meta_multiple.html", "header": "X-Second",
     "value": "Second", "desc": "second of multiple"},
    {"type": "meta", "path": "meta_multiple.html", "header": "X-Third",
     "value": "Third", "desc": "third of multiple"},
    {"type": "meta", "path": "meta_multiple.html", "header": "X-Fourth",
     "value": "Fourth", "desc": "fourth of multiple"},
    {"type": "meta", "path": "meta_malformed.html", "header": "X-Valid",
     "value": "ValidValue", "desc": "valid meta with malformed neighbors"},
    {"type": "meta", "path": "meta_malformed.html", "header": "X-After-Bad",
     "value": "AfterBad", "desc": "valid meta after malformed tags"},
    {"type": "meta", "path": "meta_special_chars.html", "header": "X-Special",
     "value": "Value-with-dashes", "desc": "dashes in content"},
    {"type": "meta", "path": "meta_special_chars.html", "header": "X-Numbers123",
     "value": "123", "desc": "numbers in header name"},
    {"type": "meta", "path": "meta_special_chars.html", "header": "X-Mixed",
     "value": "text/html; charset=utf-8", "desc": "complex content value"},
    {"type": "meta", "path": "meta_contenttype.html", "header": "X-Other",
     "value": "OtherValue", "desc": "other header with Content-Type present",
     # 2.4.x: a page whose Content-Type meta declares a charset is consumed by
     # the xml2enc charset path, so mod_proxy_html's metafix emits no http-equiv
     # headers for it and the trailing X-Other is never extracted.
     "xfail_24": "mod_proxy_html metafix extracts no header when a charset "
                 "Content-Type meta precedes it (2.4.x)"},
    {"type": "meta", "path": "meta_edge_cases.html", "header": "X-Empty-Content",
     "value": "", "desc": "empty content value",
     # metafix locates the value via a case-insensitive search for "content";
     # the header name "X-Empty-Content" matches first, so no value is
     # extracted. A metafix limitation (header name containing "content").
     "xfail_24": "metafix cannot extract a header whose name contains "
                 "'content' (X-Empty-Content)"},
    {"type": "meta", "path": "meta_edge_cases.html",
     "header": "X-Very-Long-Name-With-Many-Characters",
     "value": "LongNameTest", "desc": "long header name"},
    {"type": "meta", "path": "meta_edge_cases.html", "header": "X-End",
     "value": "LastValue", "desc": "meta at end of head"},
    # Basic URL rewriting tests
    {"type": "url_rewrite", "path": "url_rewrite/url_rewrite.html",
     "pattern": r"http://b\.example\.com/page1\.html", "desc": "basic URL rewrite in href"},
    {"type": "url_rewrite", "path": "url_rewrite/url_rewrite.html",
     "pattern": r"http://b\.example\.com/dir/page2\.html",
     "desc": "basic URL rewrite in href with path"},
    {"type": "url_rewrite", "path": "url_rewrite/url_rewrite.html",
     "pattern": r"http://b\.example\.com/image\.png", "desc": "basic URL rewrite in img src"},
    {"type": "url_rewrite", "path": "url_rewrite/url_rewrite.html",
     "pattern": r"http://b\.example\.com/submit", "desc": "basic URL rewrite in form action"},
    # Regex URL rewriting tests
    {"type": "url_rewrite", "path": "regex_rewrite/regex_rewrite.html",
     "pattern": r"http://www\.example\.com/server1\.example\.com/path/page\.html",
     "desc": "regex URL rewrite server1"},
    {"type": "url_rewrite", "path": "regex_rewrite/regex_rewrite.html",
     "pattern": r"http://www\.example\.com/server2\.example\.com/path/page\.html",
     "desc": "regex URL rewrite server2"},
    {"type": "url_rewrite", "path": "regex_rewrite/regex_rewrite.html",
     "pattern": r"http://www\.example\.com/server3\.example\.com/path/page\.html",
     "desc": "regex URL rewrite server3"},
    # Multiple HTML elements tests
    {"type": "url_rewrite", "path": "links_elements/links_elements.html",
     "pattern": r"http://rewritten\.example\.com/page\.html", "desc": "rewrite anchor href"},
    {"type": "url_rewrite", "path": "links_elements/links_elements.html",
     "pattern": r"http://rewritten\.example\.com/img\.jpg", "desc": "rewrite img src"},
    {"type": "url_rewrite", "path": "links_elements/links_elements.html",
     "pattern": r"http://rewritten\.example\.com/style\.css", "desc": "rewrite link href"},
    {"type": "url_rewrite", "path": "links_elements/links_elements.html",
     "pattern": r"http://rewritten\.example\.com/script\.js", "desc": "rewrite script src"},
    {"type": "url_rewrite", "path": "links_elements/links_elements.html",
     "pattern": r"http://rewritten\.example\.com/map\.html", "desc": "rewrite area href"},
    {"type": "url_rewrite", "path": "links_elements/links_elements.html",
     "pattern": r"http://rewritten\.example\.com/form", "desc": "rewrite form action"},
    {"type": "url_rewrite", "path": "links_elements/links_elements.html",
     "pattern": r"http://rewritten\.example\.com/object\.swf", "desc": "rewrite object data"},
    # Case-insensitive URL mapping tests
    {"type": "url_rewrite", "path": "case_insensitive/case_insensitive.html",
     "pattern": r"http://b\.example\.com/page\.html",
     "desc": "case-insensitive rewrite uppercase"},
    # ProxyHTMLExtended tests (inline scripts/CSS)
    {"type": "url_rewrite", "path": "inline_script/inline_script.html",
     "pattern": r"url\('http://b\.example\.com/bg\.png'\)",
     "desc": "CSS URL rewrite in style block"},
    {"type": "url_rewrite", "path": "inline_script/inline_script.html",
     "pattern": r"http://b\.example\.com/data\.json", "desc": "JS URL rewrite in script block"},
    {"type": "url_rewrite", "path": "inline_script/inline_script.html",
     "pattern": r"http://b\.example\.com/redirect\.html",
     "desc": "JS URL rewrite in window.location"},
    {"type": "url_rewrite", "path": "inline_script/inline_script.html",
     "pattern": r"http://b\.example\.com/api", "desc": "JS URL rewrite in onload event"},
    {"type": "url_rewrite", "path": "inline_script/inline_script.html",
     "pattern": r"http://b\.example\.com/popup\.html", "desc": "JS URL rewrite in onclick event"},
    # ProxyHTMLStripComments tests
    {"type": "comment", "path": "comments_strip/comments.html",
     "pattern": r"<!-- This is a comment that should be stripped -->", "negate": True,
     "desc": "comment is stripped"},
    {"type": "comment", "path": "comments_strip/comments.html",
     "pattern": r"Visible content", "desc": "visible content preserved"},
    {"type": "comment", "path": "comments_strip/comments.html",
     "pattern": r"More content", "desc": "more visible content preserved"},
    {"type": "comment", "path": "comments_keep/comments.html",
     "pattern": r"Visible content", "desc": "visible content still there"},
    # ProxyHTMLFixups tests
    {"type": "url_rewrite", "path": "fixups_case/fixups_case.html",
     "pattern": r"http://b\.example\.com/path/with/caps\.html",
     "desc": "lowercase fixup mixed case"},
    {"type": "url_rewrite", "path": "fixups_case/fixups_case.html",
     "pattern": r"http://b\.example\.com/all/uppercase\.html",
     "desc": "lowercase fixup all caps"},
    {"type": "url_rewrite", "path": "fixups_dospath/fixups_dospath.html",
     "pattern": r"http://a\.example\.com/path/with/backslashes\.html",
     "desc": "dospath fixup href"},
    {"type": "url_rewrite", "path": "fixups_dospath/fixups_dospath.html",
     "pattern": r"http://a\.example\.com/images/photo\.jpg", "desc": "dospath fixup img src"},
    # ProxyHTMLDocType test
    {"type": "url_rewrite", "path": "doctype/doctype.html",
     "pattern": r"<!DOCTYPE html", "desc": "DOCTYPE declaration added"},

    # Multi-substitution buffer reallocation tests
    # Tests that many literal substitutions (where replacement > match) in a
    # single buffer don't truncate content when ap_varbuf_grow reallocates.
    {"type": "url_rewrite", "path": "multi_subst/multi_subst.html",
     "pattern": r"http://long-rewritten-path\.example\.com/u01",
     "desc": "CDATA multi-subst first URL rewritten"},
    {"type": "url_rewrite", "path": "multi_subst/multi_subst.html",
     "pattern": r"http://long-rewritten-path\.example\.com/u40",
     "desc": "CDATA multi-subst last URL rewritten"},
    {"type": "url_rewrite", "path": "multi_subst/multi_subst.html",
     "pattern": r"CDATA_END_OK",
     "desc": "CDATA content preserved after multi-substitution"},
    {"type": "url_rewrite", "path": "multi_subst/multi_subst.html",
     "pattern": r"EVENT_END_OK",
     "desc": "event attr preserved after multi-substitution"},

    # Multi-substitution regex buffer tests
    # Tests that many regex substitutions in a single CDATA/event buffer
    # don't cause heap overflow or content truncation.
    {"type": "url_rewrite", "path": "multi_subst_rx/multi_subst_rx.html",
     "pattern": r"http://regex-rewritten-path\.example\.com/u01",
     "desc": "CDATA regex multi-subst first URL rewritten"},
    {"type": "url_rewrite", "path": "multi_subst_rx/multi_subst_rx.html",
     "pattern": r"http://regex-rewritten-path\.example\.com/u40",
     "desc": "CDATA regex multi-subst last URL rewritten"},
    {"type": "url_rewrite", "path": "multi_subst_rx/multi_subst_rx.html",
     "pattern": r"RX_CDATA_END_OK",
     "desc": "CDATA content preserved after regex multi-substitution"},
    {"type": "url_rewrite", "path": "multi_subst_rx/multi_subst_rx.html",
     "pattern": r"RX_EVENT_END_OK",
     "desc": "event attr preserved after regex multi-substitution"},

    # Multiple URL maps tests
    {"type": "url_rewrite", "path": "multiple_maps/multiple_maps.html",
     "pattern": r"http://new-a\.example\.com/page1\.html", "desc": "first URL map"},
    {"type": "url_rewrite", "path": "multiple_maps/multiple_maps.html",
     "pattern": r"http://new-c\.example\.com/page2\.html", "desc": "second URL map"},
    {"type": "url_rewrite", "path": "multiple_maps/multiple_maps.html",
     "pattern": r"http://new-d\.example\.com/page3\.html", "desc": "third URL map"},
]


@need_module("proxy_html", "proxy")
@pytest.mark.parametrize("t", TESTS, ids=lambda t: t["desc"])
def test_proxy_html(http, t):
    r = http.GET("/modules/html_proxy/" + t["path"])

    if t["type"] == "content":
        assert t_cmp(r.status_code, 200), f"fetching {t['path']}"
        assert t_cmp(r.headers.get("Content-Type"), re.compile(t["content_type"])), \
            f"content-type header test for {t['path']}"
        assert t_cmp(r.text, re.compile(t["content"])), f"content test for {t['path']}"

    elif t["type"] == "meta":
        assert t_cmp(r.status_code, 200), f"fetching {t['path']} for {t['desc']}"
        assert t_cmp(r.headers.get("Content-Type"), re.compile(r"text/html")), \
            f"content-type for {t['path']}"
        if t.get("xfail_24") and not http.have_min_apache_version("2.5.0"):
            pytest.xfail(t["xfail_24"])
        assert t_cmp(r.headers.get(t["header"]), t["value"]), \
            f"meta header {t['header']} = '{t['value']}' ({t['desc']})"

    elif t["type"] == "url_rewrite":
        assert t_cmp(r.status_code, 200), f"fetching {t['path']} for {t['desc']}"
        assert t_cmp(r.text, re.compile(t["pattern"], re.IGNORECASE)), t["desc"]

    elif t["type"] == "comment":
        assert t_cmp(r.status_code, 200), f"fetching {t['path']} for {t['desc']}"
        if t.get("negate"):
            assert not t_cmp(r.text, re.compile(t["pattern"])), t["desc"]
        else:
            assert t_cmp(r.text, re.compile(t["pattern"])), t["desc"]
