"""Translated from t/modules/actions.t -- mod_actions tests.

Two groups: ``tests_action`` (GET each url, check code; if 200 check body) and
``tests_script`` (GET, POST and PUT against script locations).
"""

import pytest

from apache_pytest import need_module, t_cmp

# (url, expected-code[, expected-body])
TESTS_ACTION = [
    ("mod_actions/", 200, "nada"),
    ("modules/actions/action/test.xyz", 404),
    ("modules/actions/action/test.xyz1", 404),
    ("modules/actions/action/test.xyz22", 404),
    ("modules/actions/action/test.xyz2", 200, "nada"),
]

# Added when httpd >= 2.4.60.
TESTS_ACTION_2460 = [
    ("/cgi_mod_actions/action.sh?my-file-type2:/modules/actions/action/dummy", 404),
    ("/cgi_mod_actions/action.sh?server-status:/dne", 404),
]

TESTS_SCRIPT = [
    ("modules/actions/script/test.x", 404),
    ("modules/actions/script/test.x?foo=bar", 200, "foo=bar"),
]


@need_module("mod_actions")
@pytest.mark.parametrize("case", TESTS_ACTION + TESTS_ACTION_2460,
                         ids=lambda c: c[0])
def test_actions_action(http, case):
    if case in TESTS_ACTION_2460 and not http.have_min_apache_version("2.4.60"):
        pytest.skip("requires httpd >= 2.4.60")
    url, code = case[0], case[1]
    r = http.GET(url)
    assert t_cmp(r.status_code, code), f"Check {url} for {code}"
    if code == 200:
        assert t_cmp(r.text, case[2])


@need_module("mod_actions")
@pytest.mark.parametrize("case", TESTS_SCRIPT, ids=lambda c: c[0])
def test_actions_script(http, case):
    url, code = case[0], case[1]
    r = http.GET(url)
    assert t_cmp(r.status_code, code), f"Check {url} for {code}"
    if code == 200:
        assert t_cmp(r.text, case[2])

    r = http.POST(url, content="foo2=bar2")
    assert t_cmp(r.status_code, 200)
    assert t_cmp(r.text, "POST\nfoo2: bar2\n")

    # Method not allowed
    r = http.PUT(url, content="foo2=bar2")
    assert t_cmp(r.status_code, 405)
