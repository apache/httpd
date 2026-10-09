r"""Translated from t/filter/case_in.t -- CaseFilterIn input filter (uppercasing).

Perl original (plan tests => 1 + available modules, need_module 'case_filter_in'):
    ok 1;
    my $data = "v1=one&v3=two&v2=three";
    my @filter = ('X-AddInputFilter' => 'CaseFilterIn');
    for available module/url: my $r = POST $url, @filter, content => $data; verify($r);
    sub verify { ok $r->code==200 and $body and $body=~/[A-Z]/ and $body!~/[a-z]/ }

Requires the case_filter_in C test module. The per-module URLs (php/cgi/echo_post)
are only checked when those modules are present.
"""

import re

import pytest

from apache_pytest import need_module

FILTER = {"X-AddInputFilter": "CaseFilterIn"}
DATA = "v1=one&v3=two&v2=three"

URLS = {
    "mod_php4": "/php/var3u.php",
    "mod_cgi": "/modules/cgi/perl_echo.pl",
    "mod_echo_post": "/echo_post",
}


def _verify(r):
    body = r.text
    assert r.status_code == 200
    assert body
    assert re.search(r"[A-Z]", body)
    assert not re.search(r"[a-z]", body)


@need_module("case_filter_in")
def test_case_filter_in_smoke():
    # Perl emits a bare `ok 1` first; the meaningful checks are per-module below.
    assert True


@need_module("case_filter_in")
@pytest.mark.parametrize("module", sorted(URLS), ids=lambda m: m)
def test_case_filter_in_module(http, module):
    if not http.have_module(module):
        pytest.skip(f"{module} not available")
    r = http.POST(URLS[module], content=DATA, headers=FILTER)
    _verify(r)
