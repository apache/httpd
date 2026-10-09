r"""Translated from t/apache/iffile.t -- <IfFile> section (quoted paths fixed
in 2.4.35).

Needs: mod_headers, need_min_apache_version('2.4.35').
"""

from apache_pytest import need_min_apache_version, need_module, t_cmp


@need_module("mod_headers")
@need_min_apache_version("2.4.35")
def test_iffile(http):
    resp = http.GET("/apache/iffile/document")
    assert t_cmp(resp.status_code, 200)
    assert t_cmp(
        resp.headers.get("X-Out"),
        "success1, success2, success3, success4, success5",
    )
