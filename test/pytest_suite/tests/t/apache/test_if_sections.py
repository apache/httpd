r"""Translated from t/apache/if_sections.t -- <If> section merging.

Requests various URLs in the if_sec vhost setup with a set of In-If<N> request
headers and checks the merged Out-Trace response header. The richer
(nested-section) cases only run on >= 2.4.26.

Needs: need_lwp, mod_headers, mod_proxy, mod_proxy_http,
       need_min_apache_version('2.3.8').
"""

from apache_pytest import (
    need_lwp,
    need_min_apache_version,
    need_module,
    t_cmp,
)

# (url, space-separated In-If header numbers, expected Out-Trace)
BASE_CASES = [
    ("/", "", None),
    ("/foo.if_test", "", None),
    ("/foo.if_test", "1", "global1"),
    ("/foo.if_test", "1 2", "global1, files2"),
    ("/dir/foo.txt", "1 2", "global1, dir1, dir2, dir_files1"),
    ("/dir/", "1 2", "global1, dir1, dir2"),
    ("/loc/", "1 2", "global1, loc1, loc2"),
    ("/loc/foo.txt", "1 2", "global1, loc1, loc2"),
    ("/loc/foo.if_test", "1 2", "global1, files2, loc1, loc2"),
    ("/proxy/", "1 2", "global1, locp1, locp2"),
    ("/proxy/", "2", "locp2"),
]

NESTED_CASES = [
    ("/foo.if_test", "1 11", "global1, nested11, nested113"),
    ("/foo.if_test", "1 11 111", "global1, nested11, nested111"),
    ("/foo.if_test", "1 11 112", "global1, nested11, nested112"),
    ("/dir/", "1 11", "global1, dir1, nested11, nested113"),
    ("/dir/", "1 11 111", "global1, dir1, nested11, nested111"),
    ("/dir/", "1 11 112", "global1, dir1, nested11, nested112"),
    ("/loc/", "1 11", "global1, loc1, nested11, nested113"),
    ("/loc/", "1 11 111", "global1, loc1, nested11, nested111"),
    ("/loc/", "1 11 112", "global1, loc1, nested11, nested112"),
    ("/loc/foo.if_test", "1 2 11", "global1, files2, loc1, loc2, nested11, nested113"),
    ("/loc/foo.if_test", "1 2 11 111", "global1, files2, loc1, loc2, nested11, nested111"),
    ("/loc/foo.if_test", "1 2 11 112", "global1, files2, loc1, loc2, nested11, nested112"),
]


@need_lwp()
@need_module("mod_headers", "mod_proxy", "mod_proxy_http")
@need_min_apache_version("2.3.8")
def test_if_sections(http):
    cases = list(BASE_CASES)
    if http.have_min_apache_version("2.4.26"):
        cases += NESTED_CASES
    for url, setspec, expect in cases:
        full = "/if_sec" + url
        headers = {}
        for n in setspec.split():
            headers[f"In-If{n}"] = "1"
        r = http.GET(full, headers=headers)
        assert t_cmp(r.status_code, 200), f"{full} with {setspec!r}"
        assert t_cmp(r.headers.get("Out-Trace"), expect), f"{full} with {setspec!r}"
