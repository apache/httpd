"""Translated from t/security/CVE-2004-0811.t -- access control bypass.

Perl original (plan tests => 8, need_apache(2)):
    foreach my $y (1..4) {
        ok t_cmp(GET_RC("/security/CAN-2004-0811/sub/"), 200, "subdir access allowed");
    }
    foreach my $z (1..4) {
        ok t_cmp(GET_RC("/security/CAN-2004-0811/"), 401, "topdir access denied");
    }
"""

import pytest

from apache_pytest import t_cmp


@pytest.mark.parametrize("_iter", range(1, 5))
def test_subdir_access_allowed(http, _iter):
    if not http.have_apache(2):
        pytest.skip("needs Apache 2")
    assert t_cmp(http.GET_RC("/security/CAN-2004-0811/sub/"), 200), "subdir access allowed"


@pytest.mark.parametrize("_iter", range(1, 5))
def test_topdir_access_denied(http, _iter):
    if not http.have_apache(2):
        pytest.skip("needs Apache 2")
    assert t_cmp(http.GET_RC("/security/CAN-2004-0811/"), 401), "topdir access denied"
