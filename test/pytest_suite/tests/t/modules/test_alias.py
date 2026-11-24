"""Translated from t/modules/alias.t -- mod_alias (Alias/Redirect/ScriptAlias).

Covers simple Alias, AliasMatch (/ali[0-9]), expression alias matches
(2.4.19+), Redirect status codes, RedirectMatch body/status (plain and expr),
ScriptAlias / ScriptAliasMatch CGI execution, and relative-redirect handling
(2.5.1+).

Perl original used ``need need_module('alias'), need_lwp`` and disabled LWP
redirect-following (the Python client does not follow redirects by default).
WINFU (Windows) branches are not reproduced (POSIX shell CGI assumed).
"""

import os
import re
import stat
import sys

import pytest

from apache_pytest import need_lwp, need_module, t_cmp

# name -> redirect status
REDIRECT = {
    "perm": "301",
    "perm2": "301",
    "temp": "302",
    "temp2": "302",
    "seeother": "303",
    "gone": "410",
    "forbid": "403",
}

# RedirectMatch returning a body (the matched digit)
RM_BODY = {"p": "301", "t": "302"}
# RedirectMatch returning a status code
RM_RC = {"s": "303", "g": "410", "f": "403"}

# path -> Location regex (None means a 500 with no Location)
RELATIVE_REDIRECTS = {
    "/redirect_relative/default": "^http",      # absolute
    "/redirect_relative/on": "^/out-on",        # relative
    "/redirect_relative/off": "^http",          # absolute
    "/redirect_relative/off/fail": None,        # 500, invalid URL
}

CGI_STRING = "this is a shell script cgi."
CGI = f"""#!/bin/sh
echo Content-type: text/plain
echo
echo {CGI_STRING}
"""


@need_module("alias")
@need_lwp()
def test_simple_alias(http):
    assert t_cmp(http.GET_RC("/alias/"), 200), "/alias/"
    assert t_cmp(http.GET_RC("/bogu/"), 404), "/bogu/"


@need_module("alias")
@need_lwp()
@pytest.mark.parametrize("i", range(10))
def test_aliasmatch(http, i):
    assert t_cmp(http.GET_BODY(f"/ali{i}"), i), f"/ali{i}"


@need_module("alias")
@need_lwp()
@pytest.mark.parametrize("i", range(10))
def test_expr_aliasmatch(http, i):
    if not http.have_min_apache_version("2.4.19"):
        pytest.skip("expression alias requires httpd >= 2.4.19")
    assert t_cmp(http.GET_BODY(f"/expr/ali{i}"), i), f"/ali{i}"


@need_module("alias")
@need_lwp()
@pytest.mark.parametrize("name,code", sorted(REDIRECT.items()))
def test_redirect_codes(http, name, code):
    assert t_cmp(http.GET_RC(f"/{name}"), code), f"/{name}"


@need_module("alias")
@need_lwp()
@pytest.mark.parametrize("name", sorted(RM_BODY))
@pytest.mark.parametrize("i", range(10))
def test_redirectmatch_body(http, name, i):
    # RedirectMatch sends a redirect; LWP follows it by default here, so the
    # body is that of the target (the digit).
    assert t_cmp(http.GET_BODY(f"/{name}{i}", redirect_ok=True), i), f"/{name}{i}"


@need_module("alias")
@need_lwp()
@pytest.mark.parametrize("name", sorted(RM_BODY))
@pytest.mark.parametrize("i", range(10))
def test_redirectmatch_body_expr(http, name, i):
    if not http.have_min_apache_version("2.4.19"):
        pytest.skip("expression RedirectMatch requires httpd >= 2.4.19")
    assert t_cmp(http.GET_BODY(f"/expr/{name}{i}", redirect_ok=True), i), \
        f"/{name}{i}"


@need_module("alias")
@need_lwp()
@pytest.mark.parametrize("name,code", sorted(RM_RC.items()))
@pytest.mark.parametrize("i", range(10))
def test_redirectmatch_rc(http, name, code, i):
    assert t_cmp(http.GET_RC(f"{name}{i}"), code), f"{name}{i}"


@need_module("alias")
@need_lwp()
@pytest.mark.parametrize("name,code", sorted(RM_RC.items()))
@pytest.mark.parametrize("i", range(10))
def test_redirectmatch_rc_expr(http, name, code, i):
    if not http.have_min_apache_version("2.4.19"):
        pytest.skip("expression RedirectMatch requires httpd >= 2.4.19")
    assert t_cmp(http.GET_RC(f"/expr/{name}{i}"), code), f"{name}{i}"


def _write_cgi(http):
    script = os.path.join(http.vars("t_dir"), "htdocs", "modules", "alias", "script")
    with open(script, "w") as f:
        f.write(CGI)
    os.chmod(script, 0o755 | stat.S_IRWXU)
    return script


@need_module("alias")
@need_lwp()
def test_scriptalias(http):
    _write_cgi(http)

    # Served as plain text at /modules/alias/script.
    body = http.GET_BODY("/modules/alias/script").replace("\r\n", "\n")
    assert t_cmp(body, CGI), "/modules/alias/script"

    if http.have_module("mod_cgi") or http.have_module("mod_cgid"):
        if sys.platform == "win32":
            pytest.skip("shell CGI scripts not available on Windows")
        # Executed as CGI at /cgi/script.
        body = http.GET_BODY("/cgi/script").replace("\r\n", "\n")
        assert t_cmp(body, f"{CGI_STRING}\n"), "/cgi/script"
        # ScriptAliasMatch.
        body = http.GET_BODY("/aliascgi-script").replace("\r\n", "\n")
        assert t_cmp(body, f"{CGI_STRING}\n"), "/aliascgi-script"
        if http.have_min_apache_version("2.4.19"):
            # ScriptAlias inside LocationMatch.
            body = http.GET_BODY("/expr/aliascgi-script").replace("\r\n", "\n")
            assert t_cmp(body, f"{CGI_STRING}\n"), "/aliascgi-script"

    # Bad ScriptAliasMatch.
    assert t_cmp(http.GET_RC("/aliascgi-nada"), 404), "/aliascgi-nada"


@need_module("alias")
@need_lwp()
@pytest.mark.parametrize("path,regex", sorted(RELATIVE_REDIRECTS.items()))
def test_relative_redirects(http, path, regex):
    if not http.have_min_apache_version("2.5.1"):
        pytest.skip("relative redirects require httpd >= 2.5.1")
    r = http.GET(path, redirect_ok=False)
    if regex is not None:
        assert t_cmp(r.status_code, "302")
        assert t_cmp(r.headers.get("Location"), re.compile(regex)), \
            f"failure on {path}"
    else:
        assert t_cmp(r.status_code, "500")
        assert t_cmp(r.headers.get("Location"), None), f"failure on {path}"
