"""Translated from t/modules/allowmethods.t -- mod_allowmethods test.

Each case is (method, allowed-path-segment, expected-status). GET/HEAD hit the
directory; POST hits a file; OPTIONS hits the directory. The 2.5.1+ cases add
the per-method reset/post/none locations.

Perl original used ``have_module 'allowmethods'`` in the plan -> @need_module.
"""

import pytest

from apache_pytest import need_module, t_cmp

GET, HEAD, POST, OPTIONS = "Get", "Head", "Post", "Options"

BASE_CASES = [
    (GET, GET, 200),
    (HEAD, GET, 200),
    (POST, GET, 405),
    (GET, HEAD, 200),
    (HEAD, HEAD, 200),
    (POST, HEAD, 405),
    (GET, POST, 405),
    (HEAD, POST, 405),
    (POST, POST, 200),
]

NEW_CASES = [
    (GET, POST + "/reset", 200),
    (POST, GET + "/post", 200),
    (GET, GET + "/post", 200),
    (OPTIONS, GET + "/post", 405),
    (GET, GET + "/none", 405),
    (GET, "NoPost", 200),
    (POST, "NoPost", 405),
    (OPTIONS, "NoPost", 200),
]


def _cases(http):
    cases = list(BASE_CASES)
    if http.have_min_apache_version("2.5.1"):
        cases += NEW_CASES
    return cases


@need_module("allowmethods")
@pytest.mark.parametrize("fct,allowed,rc", BASE_CASES + NEW_CASES,
                         ids=lambda v: str(v))
def test_allowmethods(http, fct, allowed, rc):
    if (fct, allowed, rc) in NEW_CASES and not http.have_min_apache_version("2.5.1"):
        pytest.skip("requires httpd >= 2.5.1")

    path = "/modules/allowmethods/" + allowed
    if fct == GET:
        r = http.GET(path + "/")
    elif fct == HEAD:
        r = http.HEAD(path + "/")
    elif fct == POST:
        r = http.POST(path + "/foo.txt")
    else:  # OPTIONS
        r = http.OPTIONS(path + "/")

    assert t_cmp(r.status_code, rc), f"{fct} request to /{allowed} responds {rc}"
