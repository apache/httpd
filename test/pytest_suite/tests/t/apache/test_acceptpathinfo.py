r"""Translated from t/apache/acceptpathinfo.t -- AcceptPathInfo directive.

For each mode (default/on/off), file ("", index.shtml, test.sh) and path-info
suffix ("" or "/foo/bar"), GET the URL and check the response code and the
(super-chomped) body against the expectation table from the Perl original.

Perl original needed: need_apache(2), mod_include, need_lwp.
"""

import re
import sys

import pytest

from apache_pytest import need_lwp, need_module, t_cmp

PATHINFO = "/foo/bar"

# mode -> [path-suffix, file-rc, file-body, cgi-rc, cgi-body]
TESTS = {
    "default": ["", "404", "Not Found", "200", f"_{PATHINFO}_"],
    "on": ["/on", "200", f"_{PATHINFO}_", "200", f"_{PATHINFO}_"],
    "off": ["/off", "404", "Not Found", "404", "Not Found"],
}

LOC = "/apache/acceptpathinfo"


def _super_chomp(body: str) -> str:
    body = re.sub(r"^[\n\r]*", "", body)
    body = re.sub(r"[\n\r]*$", "", body)
    body = body.replace("\n", " ")
    body = body.replace("\r", "")
    return body


def _cases(http):
    files = ["", "/index.shtml"]
    if http.have_module("mod_cgi") or http.have_module("mod_cgid"):
        files.append("/test.sh")
    for mode in TESTS:
        for file in files:
            for pinf in ["", PATHINFO]:
                if pinf == "":
                    exp_rc = "200"
                    exp_body = r"_\(none\)_"
                elif file == "":
                    exp_rc = "404"
                    exp_body = "Not Found"
                elif file == "/index.shtml":
                    exp_rc = TESTS[mode][1]
                    exp_body = TESTS[mode][2]
                else:
                    exp_rc = TESTS[mode][3]
                    exp_body = TESTS[mode][4]
                req = LOC + TESTS[mode][0] + file + pinf
                yield mode, req, exp_rc, exp_body


@need_module("include")
@need_lwp()
def test_acceptpathinfo(http):
    for mode, req, exp_rc, exp_body in _cases(http):
        if "/test.sh" in req and sys.platform == "win32":
            continue
        # Apache::TestRequest's GET follows redirects by default; the bare
        # directory request 301-redirects to add a trailing slash before the
        # index.shtml (which echoes PATH_INFO) is served.
        resp = http.GET(req, redirect_ok=True)
        assert t_cmp(resp.status_code, exp_rc), (
            f"AcceptPathInfo {mode} return code for {req}"
        )
        actual = _super_chomp(resp.text)
        assert t_cmp(actual, re.compile(exp_body)), (
            f"AcceptPathInfo {mode} body for {req}"
        )
