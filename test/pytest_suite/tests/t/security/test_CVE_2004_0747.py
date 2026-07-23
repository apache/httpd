"""Translated from t/security/CVE-2004-0747.t -- ap_resolve_env overflow.

Perl original (plan tests => 1, need_apache(2)):
    $rc = GET_RC "/security/CAN-2004-0747/";
    # On some platforms an over-long AuthName produces a graceful 500
    # rather than a crash; treat a 500 with a non-empty body as success.
    if ($rc == 500) {
        my $body = GET_BODY "/security/CAN-2004-0747/";
        $rc = 200 if length $body > 0;
    }
    ok t_cmp($rc, 200, "CAN-2004-0747 ap_resolve_env test case");
"""

from apache_pytest import t_cmp


def test_cve_2004_0747(http):
    if not http.have_apache(2):
        import pytest

        pytest.skip("needs Apache 2")
    rc = http.GET_RC("/security/CAN-2004-0747/")
    # A graceful 500 with a non-empty body counts as success (no crash).
    if rc == 500:
        body = http.GET_BODY("/security/CAN-2004-0747/")
        if len(body) > 0:
            rc = 200
    assert t_cmp(rc, 200), "CAN-2004-0747 ap_resolve_env test case"
