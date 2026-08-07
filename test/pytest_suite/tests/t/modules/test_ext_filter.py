"""Translated from t/modules/ext_filter.t -- mod_ext_filter (with CGI).

Checks an output filter (sed barbar), a slow filter process, an input filter
echoing a filtered body, and (httpd >= 2.4.0) a body-limiting filter that
returns 413. The 2.2 path runs 0 limit iterations.

Perl original used ``need need_module('ext_filter'), need_cgi`` and a
keep-alive UA.
"""

import re

import pytest

from apache_pytest import need_cgi, need_module, t_cmp


@need_module("ext_filter")
@need_cgi()
def test_ext_filter_output(http):
    content = http.GET_BODY("/apache/extfilter/out-foo/foobar.html").rstrip("\r\n")
    assert t_cmp(content, "barbar"), "sed output filter"


@need_module("ext_filter")
@need_cgi()
def test_ext_filter_slow(http):
    content = http.GET_BODY("/apache/extfilter/out-slow/foobar.html").rstrip("\r\n")
    assert t_cmp(content, "foobar"), "slow filter process"


@need_module("ext_filter")
@need_cgi()
def test_ext_filter_input(http):
    r = http.POST("/apache/extfilter/in-foo/modules/cgi/perl_echo.pl",
                  content="foobar\n")
    assert t_cmp(r.status_code, 200), "echo worked"
    assert t_cmp(r.text, "barbar\n"), "request body filtered"


@need_module("ext_filter")
@need_cgi()
def test_ext_filter_limit(http):
    if not http.have_min_apache_version("2.4.0"):
        pytest.skip("not interested in 2.2")
    # PR 60375 -- intermittent on 2.4.x; iterate a few times.
    for _ in range(10):
        r = http.POST("/apache/extfilter/out-limit/modules/cgi/perl_echo.pl",
                      content="foo and bar\n")
        assert t_cmp(r.status_code, 413), "got 413 error"
        assert t_cmp(r.text, re.compile("413 Request Entity Too Large")), \
            "got 413 error body"
