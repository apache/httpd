"""Translated from t/modules/speling.t -- mod_speling.

Each case file is requested under two paths: the CheckCaseOnly-Off location
(expected status in column index 2) and the CheckCaseOnly-On location (column
index 3). For redirect codes (not 200/404) the body must mention a corrected
filename. The "case" test (GOOD.html) is skipped on darwin (HFS is
case-insensitive but case-preserving).

Perl original used ``need 'mod_speling'``; requests had RedirectOK = 0 (the
Python client does not follow redirects by default).
"""

import re
import sys

import pytest

from apache_pytest import need_module, t_cmp

# (file, description, expected-Off-status, expected-On-status)
TESTCASES = [
    ("good.html", "normal", 200, 200),
    ("god.html", "omission", 301, 404),
    ("goood.html", "insertion", 301, 404),
    ("godo.html", "transposition", 301, 404),
    ("go_d.html", "wrong character", 301, 404),
    ("good.wrong_ext", "wrong extension", 300, 300),
    ("GOOD.wrong_ext", "NC wrong extension", 300, 300),
    ("Bad.html", "wrong filename", 404, 404),
    ("dogo.html", "double transposition", 404, 404),
    ("XooX.html", "double wrong character", 404, 404),
    ("several0.html", "multiple choice", 300, 404),
]

# macOS HFS is case-insensitive but case-preserving, so this would mislead.
if sys.platform != "darwin":
    TESTCASES.append(("GOOD.html", "case", 301, 301))

# (path-prefix, index into the case tuple for the expected status)
PATHS = [
    ("/modules/speling/nocase/", 2),
    ("/modules/speling/caseonly/", 3),
]

_REDIRECT_BODY = re.compile(r"good\.html|several1\.html")


@need_module("mod_speling")
@pytest.mark.parametrize("prefix,code_idx", PATHS, ids=lambda v: str(v))
@pytest.mark.parametrize("case", TESTCASES, ids=lambda c: c[1])
def test_speling(http, prefix, code_idx, case):
    fname, desc = case[0], case[1]
    expected = case[code_idx]

    r = http.GET(prefix + fname)
    assert t_cmp(r.status_code, expected), \
        f"Checking {desc}. Expecting: {expected}"

    # Only redirect responses carry a corrected-filename body.
    if expected not in (200, 404):
        assert t_cmp(r.text, _REDIRECT_BODY), "Redirect ok"
