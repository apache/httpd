"""Translated from t/modules/asis.t -- mod_asis tests.

Perl original:
    plan tests => 3, need_module 'asis';
    ok t_cmp(GET_BODY "/modules/asis/foo.asis", "This is asis content.\n", ...);
    ok t_cmp(GET_RC "/modules/asis/notfound.asis", 404, ...);
    ok t_cmp(GET_RC "/modules/asis/forbid.asis", 403, ...);
"""

from apache_pytest import need_module, t_cmp


@need_module("asis")
def test_asis_content(http):
    body = http.GET_BODY("/modules/asis/foo.asis")
    assert t_cmp(body, "This is asis content.\n"), "asis content OK"


@need_module("asis")
def test_asis_notfound(http):
    rc = http.GET_RC("/modules/asis/notfound.asis")
    assert t_cmp(rc, 404), "asis gave 404 error"


@need_module("asis")
def test_asis_forbidden(http):
    rc = http.GET_RC("/modules/asis/forbid.asis")
    assert t_cmp(rc, 403), "asis gave 403 error"
