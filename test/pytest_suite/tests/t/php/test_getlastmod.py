"""Translated from t/php/getlastmod.t -- need_php.

getlastmod.php prints the month name (strftime %B) of its own mtime in GMT.
The test computes the expected month from the file on disk under documentroot.
"""

import os
import time

from apache_pytest import need_php, t_cmp


@need_php()
def test_getlastmod(http):
    fname = os.path.join(http.vars("documentroot"), "php", "getlastmod.php")
    mtime = os.stat(fname).st_mtime
    month = time.strftime("%B", time.gmtime(mtime))
    assert t_cmp(http.GET_BODY("/php/getlastmod.php"), month), "getlastmod()"
