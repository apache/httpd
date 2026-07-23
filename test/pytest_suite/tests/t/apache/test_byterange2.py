r"""Translated from t/apache/byterange2.t -- ranged CGI response content.

Perl original:
    plan tests => 1, need need_min_apache_version('2.0.51'), need_cgi;
    $resp = GET_BODY "/modules/cgi/ranged.pl", Range => 'bytes=5-10/10';
    ok t_cmp($resp, "hello\n", "return correct content");
"""

from apache_pytest import need_cgi, need_min_apache_version, t_cmp


@need_min_apache_version("2.0.51")
@need_cgi()
def test_byterange2(http):
    resp = http.GET_BODY("/modules/cgi/ranged.pl", headers={"Range": "bytes=5-10/10"})
    assert t_cmp(resp, "hello\n"), "return correct content"
