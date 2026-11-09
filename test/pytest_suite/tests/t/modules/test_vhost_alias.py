"""Translated from t/modules/vhost_alias.t -- mod_vhost_alias.

Builds the VirtualDocumentRoot tree
(htdocs/modules/vhost_alias/%2/%1.4/%-2/%2+) and per-vhost VirtualScriptAlias
CGI scripts, then for each test hostname checks that the VirtualDocumentRoot
index and the VirtualScriptAlias CGI resolve to host-specific content.

Perl original used ``need need_module('vhost_alias'), need_cgi, need_lwp`` and
selected the mod_vhost_alias vhost port; SSL is not listening on this vhost.
"""

import os
import stat
import sys

import pytest

from apache_pytest import need_cgi, need_module, t_cmp

URL = "/index.html"
CGI_NAME = "test-cgi"
CGI_STRING = "test cgi for"
VHOSTS = [
    "www.vha-test.com",
    "big.server.name.from.heck.org",
    "ab.com",
    "w-t-f.net",
]
EXT = "sh"  # t_write_shell_script extension on POSIX


def _mkdir(path):
    os.makedirs(path, exist_ok=True)


def _write_shell_script(file_noext, code):
    path = f"{file_noext}.{EXT}"
    with open(path, "w") as f:
        f.write("#!/bin/sh\n" + code)
    os.chmod(path, 0o755 | stat.S_IRWXU)
    return path


def _setup(root):
    _mkdir(root)
    for vh in VHOSTS:
        part = vh.split(".")
        d = root + "/"

        # %2
        d += part[1] if len(part) > 1 and part[1] else "_"
        _mkdir(d)

        d += "/"
        # %1.4 (4th char of first label, 1-based index 3)
        d += part[0][3] if len(part[0]) >= 4 else "_"
        _mkdir(d)

        d += "/"
        # %-2 (second-to-last label)
        d += part[len(part) - 2] if len(part) >= 2 and part[len(part) - 2] else "_"
        _mkdir(d)

        d += "/"
        # %2+ (labels from the 2nd onward, dot-joined)
        d += ".".join(part[1:])
        _mkdir(d)

        # index.html for the VirtualDocumentRoot
        with open(f"{d}{URL}", "w") as f:
            f.write(vh)

        # VirtualScriptAlias CGI
        d = f"{root}/{vh}"
        _mkdir(d)
        d += "/"
        cgi_content = (
            "echo Content-type: text/html\n"
            "echo\n"
            f"echo {CGI_STRING} {vh}\n"
        )
        _write_shell_script(f"{d}{CGI_NAME}", cgi_content)


@need_module("vhost_alias")
@need_cgi()
@pytest.mark.skipif(sys.platform == "win32", reason="uses shell CGI scripts")
@pytest.mark.parametrize("vh", VHOSTS)
def test_vhost_alias(http, vh):
    root = os.path.join(http.vars("documentroot"), "modules", "vhost_alias")
    _setup(root)

    http.scheme("http")  # ssl not listening on this vhost
    http.module("mod_vhost_alias")  # use this module's port

    # VirtualDocumentRoot
    assert t_cmp(http.GET_BODY(URL, headers={"Host": vh}), vh), \
        "VirtalDocumentRoot test"

    # VirtualScriptAlias
    cgi_uri = f"/cgi-bin/{CGI_NAME}.{EXT}"
    actual = http.GET_BODY(cgi_uri, headers={"Host": vh}).rstrip("\r\n")
    assert t_cmp(actual, f"{CGI_STRING} {vh}"), "VirtualScriptAlias test"


# VirtualDocumentRoot of the vhost_alias_bounds vhost is
# BOUNDS_PREFIX + "%1/%0" + BOUNDS_SUFFIX, expanded into a HUGE_STRING_LEN
# buffer that is flushed whenever the next piece would not fit.
HUGE_STRING_LEN = 8192
BOUNDS_PREFIX = "/vhost-alias-bounds/"
BOUNDS_SUFFIX = "/end"


def _bounds_host(total, first):
    """A host whose expansion is ``total`` bytes, with a ``first``-byte %1."""
    rest = total - len(BOUNDS_PREFIX) - len(BOUNDS_SUFFIX) - 2 - 2 * first
    return "a" * first + "." + "b" * rest


@need_module("vhost_alias", "headers")
@pytest.mark.parametrize("total,first", [
    # short of / exactly at / just past the buffer, on the final literal
    (HUGE_STRING_LEN - 1, 2000),
    (HUGE_STRING_LEN, 2000),
    (HUGE_STRING_LEN + 1, 2000),
    # %0 ends exactly at the buffer, "/end" goes after the flush
    (HUGE_STRING_LEN + len(BOUNDS_SUFFIX), 2000),
    # %0 does not fit and is flushed mid-expansion
    (HUGE_STRING_LEN + 2834, 3000),
])
def test_vhost_alias_buffer_bounds(http, total, first):
    host = _bounds_host(total, first)
    expected = f"{BOUNDS_PREFIX}{'a' * first}/{host}{BOUNDS_SUFFIX}"
    assert len(expected) == total

    http.scheme("http")
    http.module("vhost_alias_bounds")
    res = http.GET("/", headers={"Host": host})
    assert res.headers.get("X-Document-Root") == expected
