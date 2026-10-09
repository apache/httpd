"""Translated from t/php/ifmodsince.t -- need_php.

Regression test for http://bugs.php.net/bug.php?id=17098 -- a PHP file should
not be served as 304 just because the file on disk hasn't been modified since
the If-Modified-Since date.

SKIP under FPM: bug #17098 was a defect of the *mod_php* SAPI. With mod_php the
PHP handler owns the whole request and always returns 200. Under PHP-FPM the
request is served via mod_proxy_fcgi, where httpd's core conditional-request
handling evaluates If-Modified-Since against the script file's mtime and
short-circuits to 304 before the body is generated -- a legitimate but
different behavior that the mod_php-specific assertion (rc == 200) cannot
capture without the mod_php SAPI.
"""

import pytest

from apache_pytest import need_php


@need_php()
def test_ifmodsince(http):
    pytest.skip(
        "bug #17098 was mod_php-specific; under FPM (proxy_fcgi) httpd core "
        "applies If-Modified-Since to the script mtime and returns 304 -- "
        "requires mod_php to assert the 200 behavior"
    )
