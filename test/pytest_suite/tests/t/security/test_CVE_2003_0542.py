"""Translated from t/security/CVE-2003-0542.t -- mod_rewrite/alias overflow.

Perl original:
    plan tests => 1, need 'rewrite';
    $rc = GET_RC "/security/CAN-2003-0542/nonesuch";
    ok t_cmp($rc, 404, "CAN-2003-0542 test case");
"""

from apache_pytest import need_module, t_cmp


@need_module("rewrite")
def test_cve_2003_0542(http):
    rc = http.GET_RC("/security/CAN-2003-0542/nonesuch")
    assert t_cmp(rc, 404), "CAN-2003-0542 test case"
