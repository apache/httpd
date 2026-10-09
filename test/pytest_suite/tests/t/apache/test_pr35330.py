r"""Translated from t/apache/pr35330.t -- regression test for PR 35330.

SSI allowed for a location via .htaccess Override.

Perl original:
    plan tests => 2, need 'include';
    my $r = GET '/apache/htaccess/override/hello.shtml';
    ok t_cmp($r->code, 200, "SSI was allowed for location");
    ok t_cmp($r->content, "hello", "file was served with correct content");
"""

from apache_pytest import need_module, t_cmp


@need_module("include")
def test_pr35330(http):
    r = http.GET("/apache/htaccess/override/hello.shtml")
    assert t_cmp(r.status_code, 200), "SSI was allowed for location"
    assert t_cmp(r.text, "hello"), "file was served with correct content"
