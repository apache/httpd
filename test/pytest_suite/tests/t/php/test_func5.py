"""Translated from t/php/func5.t -- need_php.

func5.php registers a shutdown function that creates a file (path passed via the
query string). The test verifies the body, then that the file exists after the
request completes.
"""

import os
import time

from apache_pytest import need_php, t_cmp

EXPECTED = "foo() will be called on shutdown...\n"


@need_php()
def test_func5(http):
    path = http.vars("t_logs")
    fname = os.path.join(path, "func5.php.ran")
    if os.path.exists(fname):
        os.unlink(fname)

    result = http.GET_BODY(f"/php/func5.php?{fname}")
    assert t_cmp(result, EXPECTED), f"GET request for /php/func5.php?{fname}"

    time.sleep(1)
    try:
        assert t_cmp(1 if os.path.exists(fname) else 0, 1), f"{fname} exists"
    finally:
        if os.path.exists(fname):
            os.unlink(fname)
