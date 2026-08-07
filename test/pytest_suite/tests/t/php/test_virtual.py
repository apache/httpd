"""Translated from t/php/virtual.t -- need_php and mod_negotiation.

Regression test for http://bugs.php.net/bug.php?id=30446 -- virtual() subrequest
output ordering.

SKIP under FPM: virtual() is provided only by the mod_php (Apache module) SAPI;
it issues an Apache subrequest, which is impossible from an out-of-process FPM
worker. Under PHP-FPM (proxy_fcgi) the function is undefined, so the script
dies with "Call to undefined function virtual()". Requires mod_php.
"""

import pytest

from apache_pytest import need_module, need_php


@need_php()
@need_module("negotiation")
def test_virtual(http):
    pytest.skip(
        "virtual() exists only in the mod_php SAPI (issues an Apache "
        "subrequest); undefined under PHP-FPM (proxy_fcgi) -- requires mod_php"
    )
