"""Translated from t/modules/negotiation.t -- mod_negotiation tests.

Covers default-language selection, explicit variant requests, Accept-Language
obedience (plain + compressed + typemap), quality-rating preferences, a
non-existent highest-quality fallback, a typemap query-string case, and
Accept content-type negotiation (with 406 cases).

Perl original used ``need_module('negotiation') && need_cgi &&
need_module('mime')``.
"""

import pytest

from apache_pytest import need_cgi, need_module, t_cmp

EN, FR, DE, FU, BU, ZH = "en", "fr", "de", "fu", "bu", "zh-TW"

CT_TESTS = [
    ("*/*", "text/plain"),
    ("text/*", "text/plain"),
    ("text/html", "text/html"),
    ("image/*", "image/jpeg"),
    ("image/gif", "image/gif"),
    ("*", "text/plain"),  # Dubious
    # Tests which expect a 406 response
    ("", None),
    ("*bad", None),
    ("/*", None),
    ("*/", None),
    ("te/*", None),
]


def _languages(http):
    langs = [EN, FR, DE, FU]
    if http.have_min_apache_version("2.4.38"):
        langs.append(ZH)
    return langs


def _chomp(s):
    return s.rstrip("\r\n")


@need_module("negotiation", "mime")
@need_cgi()
@pytest.mark.parametrize("lang", [EN, FR, DE, FU, ZH])
def test_default_language(http, lang):
    if lang == ZH and not http.have_min_apache_version("2.4.38"):
        pytest.skip("zh-TW requires httpd >= 2.4.38")

    actual = _chomp(http.GET_BODY(f"/modules/negotiation/{lang}/"))
    assert t_cmp(actual, f"index.html.{lang}"), \
        f"Verify correct default language for index.{lang}.foo"

    actual = _chomp(http.GET_BODY(f"/modules/negotiation/{lang}/compressed/"))
    assert t_cmp(actual, f"index.html.{lang}.gz"), \
        f"Verify correct default language for index.{lang}.foo.gz"

    actual = _chomp(http.GET_BODY(f"/modules/negotiation/{lang}/two/index"))
    assert t_cmp(actual, f"index.{lang}.html"), \
        f"Verify correct default language for index.{lang}.html"


@need_module("negotiation", "mime")
@need_cgi()
@pytest.mark.parametrize("lang", [EN, FR, DE, FU, ZH])
@pytest.mark.parametrize("ext", [EN, FR, DE, FU, ZH])
def test_explicit_and_accept(http, lang, ext):
    for v in (lang, ext):
        if v == ZH and not http.have_min_apache_version("2.4.38"):
            pytest.skip("zh-TW requires httpd >= 2.4.38")

    # Explicitly request all language files.
    resp = http.GET(f"/modules/negotiation/{lang}/index.html.{ext}")
    assert t_cmp(resp.status_code, 200), f"Explicitly request {lang}/index.html.{ext}"
    resp = http.GET(f"/modules/negotiation/{lang}/two/index.{ext}.html")
    assert t_cmp(resp.status_code, 200), \
        f"Explicitly request {lang}/two/index.{ext}.html"

    # Even with a default language the Accept-Language header is obeyed.
    actual = _chomp(http.GET_BODY(f"/modules/negotiation/{lang}/",
                                  headers={"Accept-Language": ext}))
    assert t_cmp(actual, f"index.html.{ext}"), \
        "Verify with a default language Accept-Language still obeyed"

    actual = _chomp(http.GET_BODY(f"/modules/negotiation/{lang}/compressed/",
                                  headers={"Accept-Language": ext}))
    assert t_cmp(actual, f"index.html.{ext}.gz"), \
        "Verify with a default language Accept-Language still obeyed (compression on)"

    actual = _chomp(http.GET_BODY(f"/modules/negotiation/{lang}/two/index",
                                  headers={"Accept-Language": ext}))
    assert t_cmp(actual, f"index.{ext}.html"), \
        "Verify with a default language Accept-Language still obeyed"


@need_module("negotiation", "mime")
@need_cgi()
def test_quality_preferences(http):
    # 'fu' has the highest quality rating (0.9), so 'fu' is returned.
    accept_fu = f"{EN}; q=0.1, {FR}; q=0.4, {FU}; q=0.9, {DE}; q=0.2"
    actual = _chomp(http.GET_BODY(f"/modules/negotiation/{EN}/",
                                  headers={"Accept-Language": accept_fu}))
    assert t_cmp(actual, f"index.html.{FU}"), \
        "fu has a higher quality rating, so we expect fu"

    actual = _chomp(http.GET_BODY(f"/modules/negotiation/{EN}/two/index",
                                  headers={"Accept-Language": accept_fu}))
    assert t_cmp(actual, f"index.{FU}.html"), \
        "fu has a higher quality rating, so we expect fu"

    actual = _chomp(http.GET_BODY(f"/modules/negotiation/{EN}/compressed/",
                                  headers={"Accept-Language": accept_fu}))
    assert t_cmp(actual, f"index.html.{FU}.gz"), \
        "fu has a higher quality rating, so we expect fu"

    # 'bu' has highest quality but is non-existent, so 'fr' is next best.
    accept_bu = f"{EN}; q=0.1, {FR}; q=0.4, {BU}; q=1.0"
    actual = _chomp(http.GET_BODY(f"/modules/negotiation/{EN}/",
                                  headers={"Accept-Language": accept_bu}))
    assert t_cmp(actual, f"index.html.{FR}"), \
        "bu has the highest quality but is non-existant, so fr is next best"

    actual = _chomp(http.GET_BODY(f"/modules/negotiation/{EN}/two/index",
                                  headers={"Accept-Language": accept_bu}))
    assert t_cmp(actual, f"index.{FR}.html"), \
        "bu has the highest quality but is non-existant, so fr is next best"

    actual = _chomp(http.GET_BODY(f"/modules/negotiation/{EN}/compressed/",
                                  headers={"Accept-Language": accept_bu}))
    assert t_cmp(actual, f"index.html.{FR}.gz"), \
        "bu has the highest quality but is non-existant, so fr is next best"


@need_module("negotiation", "mime")
@need_cgi()
def test_query_typemap(http):
    actual = _chomp(http.GET_BODY("/modules/negotiation/query/test?foo"))
    assert t_cmp(actual.replace("\r", ""), "QUERY_STRING --> foo"), \
        "The type map gives the script the highest quality; query string included"


@need_module("negotiation", "mime")
@need_cgi()
@pytest.mark.parametrize("accept,expected", CT_TESTS, ids=lambda v: repr(v))
def test_content_type(http, accept, expected):
    r = http.GET("/modules/negotiation/content-type/test.var",
                 headers={"Accept": accept})
    if expected:
        actual = r.text.strip()
        assert t_cmp(expected, actual), "should send correct variant"
    else:
        assert t_cmp(r.status_code, 406), \
            f"expect Not Acceptable for Accept: {accept}"
