"""Translated from t/modules/directorymatch.t -- DirectoryMatch header injection.

Perl original: for each test case, GET the url and assert the response code and
that the DirectoryMatch-injected header (DMMATCH1) equals "1".
"""

import pytest

from apache_pytest import need_module, t_cmp

# (url, expected status code, header the DirectoryMatch block injects)
CASES = [
    {"url": "/index.html", "code": 200, "hname": "DMMATCH1"},
    # TODO: PR41867 (DirectoryMatch matches files)
]


@need_module("headers")
@pytest.mark.parametrize("case", CASES, ids=lambda c: c["url"])
def test_directorymatch(http, case):
    r = http.GET(case["url"])
    assert t_cmp(r.status_code, case["code"]), f"code for {case['url']}"
    assert t_cmp(r.headers.get(case["hname"]), "1"), f"check for {case['hname']}"
