"""Translated from t/modules/env.t -- mod_env (with mod_include) tests.

For each variable, GET the corresponding .shtml page and compare the (chomped)
body to the expected value. ``host`` expects $APACHE_TEST_HOSTNAME.

Perl original used ``need_module('env', 'include')``.
"""

import os

import pytest

from apache_pytest import need_module, t_cmp

# name -> expected body. ``host`` is filled from the environment at runtime.
TESTS = {
    "host": os.environ.get("APACHE_TEST_HOSTNAME"),
    "set": "mod_env test environment variable",
    "setempty": "",
    "unset": "(none)",
    "type": "(none)",
    "nothere": "(none)",
}


@need_module("env", "include")
@pytest.mark.parametrize("name", sorted(TESTS))
def test_env(http, name):
    expected = TESTS[name]
    if name == "host" and expected is None:
        pytest.skip("APACHE_TEST_HOSTNAME not set")
    actual = http.GET_BODY(f"/modules/env/{name}.shtml")
    actual = actual.rstrip("\r\n")
    assert t_cmp(actual, expected), f"{name}: /modules/env/{name}.shtml"
