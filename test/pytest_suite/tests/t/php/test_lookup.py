"""Translated from t/php/lookup.t -- need_php (apache_lookup_uri).

SKIP under FPM: apache_lookup_uri() is provided only by the mod_php (Apache
module) SAPI. Under PHP-FPM (proxy_fcgi) the function is undefined, so the
script dies with "Call to undefined function apache_lookup_uri()". This test
(and the bug #31645 header regression it builds on) cannot run without mod_php.
"""

import pytest

from apache_pytest import need_php


@need_php()
def test_lookup(http):
    pytest.skip(
        "apache_lookup_uri() exists only in the mod_php SAPI; undefined under "
        "PHP-FPM (proxy_fcgi) -- requires mod_php"
    )
