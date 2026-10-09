r"""Translated from t/apache/cfg_getline.t -- ap_cfg_getline / varbuf line reading.

Writes a `.htaccess` containing a single long ``SetEnvIf ... testvar=aaaa...``
line of a given length, then requests an SSI page that echoes the testvar value,
verifying the server parsed the long config line correctly (200 + exact value).
Exercises a range of line lengths up to the 8190-char .htaccess limit.
"""

import os

import pytest

from apache_pytest import need_lwp, need_module

LENGTHS = [100, *range(196, 203), *range(396, 403), *range(596, 603),
           *range(1016, 1031), *range(8170, 8191)]


@need_lwp()
@need_module("include")
@need_module("setenvif")
@pytest.mark.parametrize("length", LENGTHS, ids=lambda n: str(n))
def test_cfg_getline(http, config, length):
    prefix = "SetEnvIf User-Agent ^ testvar="
    expect = "a" * (length - len(prefix))
    htaccess = os.path.join(
        config.vars["serverroot"], "htdocs", "apache", "cfg_getline", ".htaccess"
    )
    with open(htaccess, "w") as fh:
        fh.write(f"{prefix}{expect}\n")

    r = http.GET("/apache/cfg_getline/index.shtml")
    assert r.status_code == 200
    assert r.text.startswith(f"'{expect}'"), f"length {length}"
