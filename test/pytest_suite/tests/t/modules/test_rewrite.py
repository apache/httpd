r"""Translated from t/modules/rewrite.t -- mod_rewrite.

Exercises RewriteMap (txt/rnd/prg), query-string append/escaping, per-dir and
server redirects, [B]/[BNE]/[BCTLS] escaping flags, bad-query handling,
RewriteCond expr, prefix-stat (via a dedicated vhost), Vary/cookie corner cases,
and (when mod_proxy / CGI are present) rewrite-to-proxy. Version-gated cases use
have_min_apache_version.

Perl original: plan tests => ..., todo => \@todo, need_module 'rewrite'.
"""

import re
import sys

import pytest

from apache_pytest import need_module, t_cmp

MAP = ["txt", "rnd", "prg"]
NUM = ["1", "2", "3", "4", "5", "6"]


def _have_proxy(http):
    return http.have_module("proxy")


def _have_cgi(http):
    return http.have_module("cgid") or http.have_module("cgi")


@need_module("rewrite")
def test_rewrite_maps(http):
    for m in MAP:
        accept = m.upper()
        for n in NUM:
            r = http.GET_BODY(f"/modules/rewrite/{n}", headers={"Accept": accept})
            r = r.rstrip("\n").replace("\r", "")
            if accept == "RND":
                assert re.match(r"^[\d]$", r), f"RND single digit, got {r!r}"
                assert re.match(rf"^[{r}-6]$", r)
            else:
                assert r == n, f"map {m} num {n}: got {r!r}"


@need_module("rewrite")
def test_rewrite_special_accepts(http):
    def body(accept):
        return http.GET_BODY("/modules/rewrite/",
                             headers={"Accept": str(accept)}).rstrip("\n").replace("\r", "")
    assert body(7) == "BIG"
    assert body(0) == "ZERO"
    assert body("lucky13") == "JACKPOT"


@need_module("rewrite")
def test_rewrite_qsa(http):
    r = http.GET_BODY("/modules/rewrite/qsa.html?baz=bee").rstrip("\r\n")
    assert t_cmp(r, re.compile(r"\r?\nQUERY_STRING = foo=bar&baz=bee\r?\n", re.S)), \
        "query-string append test"


@need_module("rewrite")
def test_rewrite_pr50447(http):
    hostport = http.hostport()
    r = http.GET("/modules/rewrite/redirect-dir.html?q=%25")
    assert t_cmp(r.status_code, 301), "per-dir redirect response code is OK"
    assert t_cmp(r.headers.get("Location"),
                 f"http://{hostport}/foobar.html?q=%25"), \
        "per-dir query-string escaping is OK"

    r = http.GET("/modules/rewrite/redirect.html?q=%25")
    assert t_cmp(r.status_code, 301), "redirect response code is OK"
    assert t_cmp(r.headers.get("Location"),
                 f"http://{hostport}/foobar.html?q=%25"), \
        "query-string escaping is OK"


@need_module("rewrite")
def test_rewrite_to_proxy(http):
    if not _have_proxy(http):
        pytest.skip("no proxy module")
    r = http.GET_BODY("/modules/rewrite/proxy.html").rstrip("\n")
    assert t_cmp(r, "JACKPOT"), "request was proxied"
    r = http.GET_BODY("/modules/proxy/rewrite/foo bar.html").rstrip("\n")
    assert t_cmp(r, "foo bar"), "per-dir proxied rewrite escaping worked"


@need_module("rewrite")
def test_rewrite_proxy_query_string(http):
    if not (_have_proxy(http) and _have_cgi(http)):
        pytest.skip("missing proxy or CGI module")
    r = http.GET_BODY("/modules/rewrite/proxy2/env.pl?fish=fowl").rstrip("\r\n")
    assert t_cmp(r, re.compile(r"QUERY_STRING = fish=fowl\r?\n", re.S)), \
        "QUERY_STRING passed OK"

    assert t_cmp(http.GET_RC("/modules/rewrite/proxy3/env.pl?horse=norman"), 404), \
        "RewriteCond QUERY_STRING test"

    r = http.GET_BODY("/modules/rewrite/proxy3/env.pl?horse=trigger").rstrip("\r\n")
    assert t_cmp(r, re.compile(r"QUERY_STRING = horse=trigger\r?\n", re.S)), \
        "QUERY_STRING passed OK"

    r = http.GET("/modules/rewrite/proxy-qsa.html?bloo=blar")
    assert t_cmp(r.status_code, 200), "proxy/QSA test success"
    assert t_cmp(r.text, re.compile(r"QUERY_STRING = foo=bar&bloo=blar\r?\n", re.S)), \
        "proxy/QSA test appended args correctly"


@need_module("rewrite", "test_utilities")
def test_rewrite_pr60478(http):
    if not http.have_min_apache_version("2.4"):
        pytest.skip("PR 60478 requires ap_expr in version 2.4")
    r = http.GET("/modules/rewrite/pr60478-rewrite-loop/a/X/b/c")
    assert t_cmp(r.status_code, 500), "PR 60478 rewrite loop is halted"


@need_module("rewrite")
def test_rewrite_vary_2429(http):
    if not http.have_min_apache_version("2.4.29"):
        pytest.skip("requires httpd >= 2.4.29")
    for host in ("test1", "test2"):
        r = http.GET("/modules/rewrite/vary1.html", headers={"Host": host})
        assert t_cmp(r.text, re.compile("VARY2")), "Correct internal redirect happened"
        vary = r.headers.get("Vary") or ""
        assert "Host" not in vary, "Vary:Host header not added"


@need_module("rewrite")
def test_rewrite_vary_2430(http):
    if not http.have_min_apache_version("2.4.30"):
        pytest.skip("requires httpd >= 2.4.30")
    r = http.GET("/modules/rewrite/vary3.html",
                 headers={"User-Agent": "directory-agent"})
    assert t_cmp(r.text, re.compile("VARY4")), "Correct internal redirect happened"
    assert t_cmp(r.headers.get("Vary"), re.compile("User-Agent")), \
        "Vary:User-Agent header added"

    r = http.GET("/modules/rewrite/vary3.html",
                 headers={"Referer": "directory-referer", "Accept": "directory-accept"})
    assert t_cmp(r.text, re.compile("VARY4"))
    assert t_cmp(r.headers.get("Vary"), re.compile("Accept")), "Vary:Accept added"

    r = http.GET("/modules/rewrite/vary3.html",
                 headers={"Referer": "directory-referer",
                          "Accept": "this-is-not-the-value-in-the-rewritecond"})
    assert t_cmp(r.text, re.compile("VARY4"))
    assert t_cmp(r.headers.get("Vary"), re.compile("Referer")), "Vary:Referer added"
    assert "Accept" not in (r.headers.get("Vary") or ""), "Vary:Accept not added"

    r = http.GET("/modules/rewrite/vary3.html", headers={"Host": "directory-domain"})
    assert t_cmp(r.text, re.compile("VARY4"))
    assert "Host" not in (r.headers.get("Vary") or ""), "Vary:Host not added"


@need_module("rewrite")
def test_rewrite_cookie_samesite(http):
    if not http.have_min_apache_version("2.4.47"):
        pytest.skip("requires httpd >= 2.4.47")
    for path, present in [("", None), ("0", None), ("false", None),
                          ("none", "SameSite=none"), ("lax", "SameSite=lax"),
                          ("foo", "SameSite=foo")]:
        r = http.GET(f"/modules/rewrite/cookie/{path}")
        sc = r.headers.get("Set-Cookie") or ""
        if present is None:
            assert "SameSite=" not in sc, f"samesite not present ({path or 'no arg'})"
        else:
            assert present in sc, f"samesite {path}"


def _escapes(http):
    cases = [
        ("/modules/rewrite/escaping/local/foo%20bar", 403),
        ("/modules/rewrite/escaping/redir_ne/foo%20bar", 403),
        ("/modules/rewrite/escaping/proxy/foo%20bar", 403),
        ("/modules/rewrite/escaping/proxy_ne/foo%20bar", 403),
        ("/modules/rewrite/escaping/fixups/local/foo%20bar", 403),
        ("/modules/rewrite/escaping/fixups/redir_ne/foo%20bar", 403),
        ("/modules/rewrite/escaping/fixups/proxy/foo%20bar", 403),
        ("/modules/rewrite/escaping/fixups/proxy_ne/foo%20bar", 403),
    ]
    if http.have_min_apache_version("2.4.57"):
        cases += [
            ("/modules/rewrite/escaping/redir/foo%20bar", 302),
            ("/modules/rewrite/escaping/fixups/redir/foo%20bar", 302),
        ]
    return cases


@need_module("rewrite")
def test_rewrite_escapes(http):
    for url, expect in _escapes(http):
        r = http.GET(url)
        assert t_cmp(r.status_code, expect), f"escape {url}"


def _bflags(http):
    cases = [
        ("/modules/rewrite/escaping/local_b/foo/bar/%20baz%0d", "foo%2fbar%2f+baz%0d"),
        ("/modules/rewrite/escaping/local_b_justslash/foo/bar/%20baz/",
         "foo%2fbar%2f baz%2f"),
    ]
    if http.have_min_apache_version("2.4.57"):
        cases += [
            ("/modules/rewrite/escaping/local_bctls/foo/bar/%20baz/%0d",
             "foo/bar/+baz/%0d"),
            ("/modules/rewrite/escaping/local_bctls_nospace/foo/bar/%20baz/%0d",
             "foo/bar/ baz/%0d"),
            ("/modules/rewrite/escaping/local_bctls_andslash/foo/bar/%20baz/%0d",
             "foo%2fbar%2f+baz%2f%0d"),
            ("/modules/rewrite/escaping/local_b_noslash/foo/bar/%20baz/%0d",
             "foo/bar/+baz/%0d"),
        ]
    return cases


@need_module("rewrite")
def test_rewrite_bflags(http):
    for url, expect in _bflags(http):
        r = http.GET(url)
        assert t_cmp(r.headers.get("rewritten-query"), expect), f"bflag {url}"


def _redirects(http):
    all_ = [
        ("/modules/rewrite/escaping/qsd-like/foo", r"/foo$",
         http.have_min_apache_version("2.4.57")),
        ("/modules/rewrite/escaping/qsd-like-plus-qsa/foo?preserve-me",
         r"/foo\?preserve-me$", http.have_min_apache_version("2.4.58")),
        ("/modules/rewrite/escaping/qsd-like-plus-qsa-qsl/foo/%3fbar/?preserve-me",
         r"/foo/%3fbar/\?preserve-me$", http.have_min_apache_version("2.4.58")),
    ]
    return [(u, e) for (u, e, on) in all_ if on]


@need_module("rewrite")
def test_rewrite_redirects(http):
    for url, expect in _redirects(http):
        r = http.GET(url)
        loc = r.headers.get("location") or ""
        assert re.search(expect, loc), f"redirect {url}: loc={loc!r}"


def _badquery(http):
    cases = [("/modules/rewrite/badquery/literal", "theval")]
    if http.have_min_apache_version("2.4.60"):
        cases += [
            ("/modules/rewrite/badquery/backref/%3ftheval", ""),
            ("/modules/rewrite/badquery/backref-map/%3ftheval", ""),
            ("/modules/rewrite/badquery/backref-optin/%3ftheval", "theval"),
        ]
    if http.have_min_apache_version("2.4.63"):
        cases += [
            ("/modules/rewrite/badquery/backref-qsa/xxx?foo%3fbar",
             "query=xxx&foo%3fbar"),
            ("/modules/rewrite/badquery/backref-qsalike/xxx?foo%3fbar",
             "query=xxx&foo%3fbar"),
            ("/modules/rewrite/badquery/backref-noqsa/xxx?foo%3fbar", "query=xxx"),
            ("/modules/rewrite/badquery/backref-noqsa-map/xxx?foo%3fbar", "query=xxx"),
            ("/modules/rewrite/badquery/backref-qslast/yyy/%3fzzz", "query=yyy"),
        ]
    return cases


@need_module("rewrite")
def test_rewrite_badquery(http):
    for url, expect in _badquery(http):
        r = http.GET(url)
        received = r.headers.get("rewritten-query") or ""
        assert t_cmp(received, expect), f"badquery {url}"


def _condexpr():
    return [
        ("/modules/rewrite/expr/notgone/false", 404),
        ("/modules/rewrite/expr/notgone/nottrue", 404),
        ("/modules/rewrite/expr/shouldredir/true", 303),
        ("/modules/rewrite/expr/shouldredir/notfalse", 303),
    ]


@need_module("rewrite")
def test_rewrite_condexpr(http):
    for url, expect in _condexpr():
        r = http.GET(url)
        assert t_cmp(r.status_code, expect), f"condexpr {url}"


def _prefixstats(http):
    docroot = http.vars("documentroot")
    serverroot = http.vars("serverroot")
    cases = [
        ("/modules/rewrite/prefixstat/index.html", 200),
        (f"/modules/rewrite/prefixstat/query/index.html?{docroot}/index.html", 200),
        (f"/modules/rewrite/prefixstat/query/index.html?{serverroot}/conf/core.conf",
         404),
    ]
    if http.have_min_apache_version("2.4.60"):
        cases.append(
            (f"/modules/rewrite/prefixstat/query-optin/index.html?"
             f"{serverroot}/conf/core.conf", 200))
    return cases


@need_module("rewrite")
@pytest.mark.skipif(sys.platform == "win32",
                    reason="Windows drive-letter colons in paths cause 400 Bad Request")
def test_rewrite_prefixstat(http):
    # Uses the rewrite_prefix_stat vhost (larger LimitRequestLine).
    http.module("rewrite_prefix_stat")
    try:
        for path, expect in _prefixstats(http):
            url = http.vhost_url("rewrite_prefix_stat", path)
            r = http.GET(url)
            assert t_cmp(r.status_code, expect), f"prefixstat {path}"
    finally:
        http.module(None)
