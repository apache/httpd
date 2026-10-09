"""Translated from t/security/CVE-2005-2491.t -- mod_rewrite/SSI overflow.

Perl original (plan tests => 2*2, need 'rewrite'):
    foreach my $dir ("one/", "two/") {
        my $r = GET("/security/CAN-2005-2491/" . $dir);
        ok t_cmp($r->message, 'Internal Server Error', 'check that server did not segfault');
        ok t_cmp($r->code, 500, "check for 500 response error");
    }
The message check rules out the client-side fake-500 generated on a segfault.
"""

import pytest

from apache_pytest import need_module, t_cmp


@need_module("rewrite")
@pytest.mark.parametrize("subdir", ["one/", "two/"])
def test_cve_2005_2491(http, subdir):
    r = http.GET("/security/CAN-2005-2491/" + subdir)
    assert t_cmp(r.reason_phrase, "Internal Server Error"), (
        "check that server did not segfault"
    )
    assert t_cmp(r.status_code, 500), "check for 500 response error"
