"""Translated from t/modules/filter.t -- mod_filter + mod_case_filter by type.

GET each URL and compare the (chomped) body to the expected case-folded text.

Perl original used ``need_cgi, need_module('mod_filter'),
need_module('mod_case_filter')``.
"""

import pytest

from apache_pytest import need_cgi, need_module, t_cmp

TESTCASES = [
    ("/modules/cgi/xother.pl", "HELLOWORLD"),
    ("/modules/filter/bytype/test.txt", "HELLOWORLD"),
    ("/modules/filter/bytype/test.xml", "HELLOWORLD"),
    ("/modules/filter/bytype/test.css", "helloworld"),
    ("/modules/filter/bytype/test.html", "helloworld"),
]


@need_cgi()
@need_module("mod_filter", "mod_case_filter")
@pytest.mark.parametrize("url,expected", TESTCASES, ids=lambda v: str(v))
def test_filter(http, url, expected):
    body = http.GET_BODY(url).rstrip("\r\n")
    assert t_cmp(body, expected)
