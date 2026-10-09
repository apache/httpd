"""Translated from t/modules/data.t -- mod_data data: URI generation.

GET the served PNG through mod_data and assert it comes back as the exact
base64 ``data:`` URI. The (very large) expected string is stored alongside this
file in ``data_expected.txt`` (extracted verbatim from the Perl test).

Perl original used ``need 'mod_data'``.
"""

import os

from apache_pytest import need_module, t_cmp

_EXPECTED_FILE = os.path.join(os.path.dirname(__file__), "data_expected.txt")

TESTCASES = [
    ("/modules/data/SupportApache-small.png", _EXPECTED_FILE),
]


@need_module("mod_data")
def test_data(http):
    for url, expected_file in TESTCASES:
        with open(expected_file, encoding="ascii") as f:
            expected = f.read()
        r = http.GET(url)
        assert t_cmp(r.status_code, 200), "Checking return code is '200'"
        assert t_cmp(r.text, expected)
