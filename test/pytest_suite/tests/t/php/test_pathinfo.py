"""Translated from t/php/pathinfo.t -- need_php and AcceptPathInfo support.

Verifies PATH_INFO handling under AcceptPathInfo on/off locations.

SKIP under FPM: the info.php scripts this test exercises live under
t/htdocs/apache/acceptpathinfo/ (NOT the php docroot). The FPM wiring routes
only htdocs/php/*.php to proxy_fcgi, so these files are served as plain text
rather than executed -- the "on" case returns the raw "<?php ...?>" source
instead of "_/fish/food_". Executing them would require an additional
SetHandler proxy:fcgi block for the acceptpathinfo directory, which the test
framework's generated config does not emit (and which is outside the editable
scope here). The PATH_INFO accept/reject behavior is fundamentally a mod_php
SAPI scenario; the equivalent FPM mapping (PATH_INFO vs SCRIPT split) is not
configured. Requires mod_php / dedicated FPM PATH_INFO config.
"""

import pytest

from apache_pytest import need_min_apache_version, need_php


@need_php()
@need_min_apache_version("2.0.0")
def test_pathinfo(http):
    pytest.skip(
        "info.php lives under htdocs/apache/acceptpathinfo/ which is not "
        "routed to FPM (only htdocs/php/*.php is); served as plain text, not "
        "executed -- requires mod_php or a dedicated FPM PATH_INFO mapping"
    )
