"""Translated from t/security/CVE-2004-0940.t -- mod_include overflow.

Perl original (plan tests => 1, need_module 'include'):
    # 1.3.32 and earlier will segfault
    ok t_cmp(GET_RC("/security/CAN-2004-0940.shtml"), 200, 'response was 200');
"""

from apache_pytest import need_module, t_cmp


@need_module("include")
def test_cve_2004_0940(http):
    assert t_cmp(http.GET_RC("/security/CAN-2004-0940.shtml"), 200), "response was 200"
