"""Translated from t/modules/status.t -- mod_status quick test.

Perl original:
    plan tests => 1, need_module 'status';
    my $servername = Apache::Test::vars()->{servername};
    my $title = "Apache Server Status for $servername";
    my $status = GET_BODY $uri;
    ok ($status =~ /$title/i);
"""

import re

from apache_pytest import need_module


@need_module("status")
def test_server_status(http):
    servername = http.vars("servername")
    title = f"Apache Server Status for {servername}"
    body = http.GET_BODY("/server-status")
    assert re.search(re.escape(title), body, re.IGNORECASE)
