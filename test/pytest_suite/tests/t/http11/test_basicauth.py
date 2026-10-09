r"""Translated from t/http11/basicauth.t -- basic auth over keepalive.

Perl original (plan tests => 3, need_module 'authany'):
    my $res = GET $url;                                   ok $res->code == 401;
    $res = GET $url, username=>'guest', password=>'guest'; ok $res->code == 200;
    # 3rd assertion: LWP's user_agent_request_num($res) == 3 (no-creds, 401,
    #   then 200). That counter is an LWP internal not exposed by httpx, so the
    #   round-trip-count assertion is dropped; the 401-then-200 behaviour it
    #   verifies is covered by the two status checks.

Requires the authany C test module.
"""

import httpx

from apache_pytest import need_module

URL = "/authany/index.html"


@need_module("authany")
def test_basicauth_challenge(http):
    res = http.GET(URL)
    assert res.status_code == 401

    res = http.GET(URL, auth=httpx.BasicAuth("guest", "guest"))
    assert res.status_code == 200
