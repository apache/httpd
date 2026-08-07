r"""Translated from t/filter/case.t -- CaseFilter output filter (uppercasing).

Perl original (plan tests => 1 + available modules, need_module 'case_filter'):
    my @filter = ('X-AddOutputFilter' => 'CaseFilter');
    verify(GET '/', @filter);
    for module with URL that is available: verify(GET $url, @filter);
    sub verify { ok $r->code==200 and $body and $body=~/[A-Z]/ and $body!~/[a-z]/ }

Requires the case_filter C test module. The per-module URLs (php/cgi/alias)
are only checked when those modules are present.
"""

import re

import pytest

from apache_pytest import need_module

# mod_client_add_filter applies the named output filter via this request header.
FILTER = {"X-AddOutputFilter": "CaseFilter"}

# module -> URL whose output should get uppercased by the filter
URLS = {
    "mod_php4": "/php/hello.php",
    "mod_cgi": "/modules/cgi/perl.pl",
    "mod_test_rwrite": "/test_rwrite",
    "mod_alias": "/getfiles-perl-pod/perlsub.pod",  # requires perl-doc on Ubuntu
}


def _verify(r):
    body = r.text
    assert r.status_code == 200
    assert body
    assert re.search(r"[A-Z]", body)
    assert not re.search(r"[a-z]", body)


@need_module("case_filter")
def test_case_filter_root(http):
    _verify(http.GET("/", headers=FILTER))


@need_module("case_filter")
@pytest.mark.parametrize("module", sorted(URLS), ids=lambda m: m)
def test_case_filter_module(http, module):
    if not http.have_module(module):
        pytest.skip(f"{module} not available")
    # The mod_alias URL downloads from the /getfiles-perl-pod alias, which is
    # only generated when perl's 'pods' dir was found (perl-doc installed).
    if module == "mod_alias" and not http.vars("perlpod"):
        pytest.skip("no perl 'pods' dir (perl-doc) for the getfiles-perl-pod alias")
    _verify(http.GET(URLS[module], headers=FILTER))
