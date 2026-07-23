"""Translated from t/modules/setenvif.t -- mod_setenvif (with mod_include).

Rewrites the htaccess for the setenvif page with BrowserMatch / SetEnvIf /
SetEnvIfNoCase / SetEnvIfExpr directives and checks the SSI page reports the
expected VAR_ONE/TWO/THREE values. ``test_all_vars`` incrementally appends
``VAR_x=set`` clauses and compares the page against the expected set (or all
"(none)" when ``exp_modifier`` is true).

Perl original used ``have_module qw(setenvif include)``.

Note: the Perl tests assume an LWP client whose User-Agent matches
``^libwww-perl/``; httpx sends its own UA, so we send a matching User-Agent
header to faithfully exercise the BrowserMatch / ^User-Ag directives.
The remote_addr var is not exposed by the Python config (framework-API gap);
we fall back to 127.0.0.1.
"""

import os
import re

import pytest

from apache_pytest import need_module, t_cmp

VARS = ["VAR_ONE", "VAR_TWO", "VAR_THREE"]
PAGE = "/modules/setenvif/htaccess/setenvif.shtml"
GOOD_UA = "^libwww-perl/.*"
BAD_UA = "foo-browser/0.1"

# The Perl tests assume an LWP client whose User-Agent matches ^libwww-perl/;
# httpx sends its own UA, so send a matching one to faithfully exercise the
# BrowserMatch ^libwww-perl/ directives. ``Connection: close`` avoids httpx
# reusing a keep-alive socket the server has closed (the Perl LWP client here
# was not keep-alive).
_UA = {"User-Agent": "libwww-perl/6.00", "Connection": "close"}


def _htaccess_path(http):
    return os.path.join(http.vars("documentroot"), "modules", "setenvif",
                        "htaccess", ".htaccess")


def _write_htaccess(http, string):
    with open(_htaccess_path(http), "w") as f:
        f.write(string)


def _set_expect(not_set, conf_str):
    """Build the expected SSI body for the given htaccess content."""
    names = {1: "VAR_ONE", 2: "VAR_TWO", 3: "VAR_THREE"}
    out = ""
    for k in sorted(names):
        v = "(none)"
        m = re.search(rf"{names[k]}=(\S+)", conf_str)
        if m and not not_set:
            v = m.group(1)
        out += f"{k}:{v}\n"
    return out


def _test_all_vars(http, exp_modifier, conf_str):
    set_val = "set"
    for var in VARS:
        conf_str += f" {var}={set_val}"
        _write_htaccess(http, conf_str)
        expected = _set_expect(exp_modifier, conf_str)
        actual = http.GET_BODY(PAGE, headers=_UA).replace("\r", "")
        assert actual == expected, f"conf:\n{conf_str}\nexpected:\n{expected}\ngot:\n{actual}"


def _var_attributes(http):
    remote_addr = http.vars("remote_addr") or "127.0.0.1"
    return {
        "Remote_Host": {"pass": remote_addr, "fail": "some.where.else.com"},
        "Remote_Addr": {"pass": remote_addr, "fail": "63.125.18.195"},
        "Request_Method": {"pass": "GET", "fail": "POST"},
        "Request_Protocol": {"pass": "HTTP", "fail": "FTP"},
        "Request_URI": {"pass": PAGE, "fail": "foo.html"},
        "^User-Ag": {"pass": GOOD_UA, "fail": BAD_UA},
    }


@need_module("setenvif", "include")
def test_setenvif_browsermatch(http):
    _test_all_vars(http, 0, f"BrowserMatch {GOOD_UA}")
    _test_all_vars(http, 1, f"BrowserMatch {BAD_UA}")


@need_module("setenvif", "include")
def test_setenvif_attributes(http):
    var_att = _var_attributes(http)
    for attribute in sorted(var_att):
        att = var_att[attribute]
        _test_all_vars(http, 0, f"SetEnvIf {attribute} {att['pass']}")
        _test_all_vars(http, 1, f"SetEnvIf {attribute} {att['fail']}")

        # relaying variables
        _test_all_vars(
            http, 0,
            f"SetEnvIf {attribute} {att['pass']} RELAY=1\nSetEnvIf RELAY 1")
        _test_all_vars(
            http, 1,
            f"SetEnvIf {attribute} {att['pass']} RELAY=1\nSetEnvIf RELAY 0")

        # SetEnvIfNoCase
        _test_all_vars(http, 0, f"SetEnvIfNoCase {attribute} {att['pass'].upper()}")
        _test_all_vars(http, 1, f"SetEnvIfNoCase {attribute} {att['fail'].upper()}")


@need_module("setenvif", "include")
def test_setenvif_relaying(http):
    _test_all_vars(http, 0, f"BrowserMatch {GOOD_UA} RELAY=1\nSetEnvIf RELAY 1")
    _test_all_vars(
        http, 0,
        f"BrowserMatch {GOOD_UA} RELAY=1\nSetEnvIf RELAY 1 R2=1\nSetEnvIf R2 1")
    _test_all_vars(
        http, 1,
        f"BrowserMatch {GOOD_UA} RELAY=1\nSetEnvIf RELAY 1 R2=1\nSetEnvIf R2 0")
    _test_all_vars(http, 1, f"BrowserMatch {GOOD_UA} RELAY=0\nSetEnvIf RELAY 1")
    _test_all_vars(http, 1, f"BrowserMatch {GOOD_UA} RELAY=1\nSetEnvIf RELAY 0")

    # test '!' -- set then unset R2
    _test_all_vars(
        http, 1,
        f"BrowserMatch {GOOD_UA} RELAY=1\nSetEnvIf RELAY 1 R2=1\n"
        f"SetEnvIf RELAY 1 !R2\nSetEnvIf R2 1")


@need_module("setenvif", "include")
def test_setenvif_expr(http):
    _test_all_vars(http, 0, r'SetEnvIfExpr "%{REQUEST_URI} =~ /\.shtml$/"')
    _test_all_vars(http, 1, r'SetEnvIfExpr "%{REQUEST_URI} =~ /\.foo$/"')


@need_module("setenvif", "include")
def test_setenvif_expr_replacement(http):
    _write_htaccess(
        http, r'SetEnvIfExpr "%{REQUEST_URI} =~ /\.(sh)tml$/" VAR_ONE=$0 VAR_TWO=$1')
    assert t_cmp(http.GET_BODY(PAGE, headers=_UA), "1:.shtml\n2:sh\n3:(none)\n")

    _write_htaccess(
        http, r'SetEnvIfExpr "%{REQUEST_URI} !~ /\.(sh)tml$/" VAR_ONE=$0 VAR_TWO=$1')
    assert t_cmp(http.GET_BODY(PAGE, headers=_UA), "1:(none)\n2:(none)\n3:(none)\n")

    _write_htaccess(
        http,
        r'SetEnvIfExpr "%{REQUEST_URI} =~ /\.(sh)tmlXXX$/" VAR_ONE=$0 VAR_TWO=$1')
    assert t_cmp(http.GET_BODY(PAGE, headers=_UA), "1:(none)\n2:(none)\n3:(none)\n")


@need_module("setenvif", "include")
def test_setenvif_expr_inverted(http):
    if not http.have_min_apache_version("2.4.38"):
        pytest.skip("inverted match test requires httpd >= 2.4.38")
    _write_htaccess(
        http,
        r'SetEnvIfExpr "%{REQUEST_URI} !~ /\.(sh)tmlXXX$/" VAR_ONE=$0 VAR_TWO=$1')
    assert t_cmp(http.GET_BODY(PAGE, headers=_UA), "1:$0\n2:$1\n3:(none)\n")


@need_module("setenvif", "include")
def test_setenvif_file_disallowed(http):
    if not http.have_min_apache_version("2.4.67"):
        pytest.skip("CVE-2026-24072 test requires httpd >= 2.4.67")
    htdocs = http.vars("documentroot")
    _write_htaccess(
        http,
        f"SetEnvIfExpr \"file('{htdocs}/foobar.html') =~ /(.+)/\" VAR_ONE=$0")
    body = http.GET_BODY(PAGE, headers=_UA)
    # file() access should be disallowed in htaccess context.
    assert not t_cmp(body, re.compile(r"^1:foobar"))
