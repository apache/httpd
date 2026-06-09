r"""Translated from t/ssl/all.t.

Trivial gate test: the whole t/ssl/ directory is skipped unless mod_ssl is
enabled (and, in Perl, LWP had https support -- always true for httpx). The
original just asserts ``ok 1`` once SSL is present.
"""

from apache_pytest import need_ssl


@need_ssl()
def test_ssl_enabled(http):
    assert http.have_module("ssl")
