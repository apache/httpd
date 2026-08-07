"""Translated from t/modules/dir.t -- mod_dir DirectoryIndex / DirectorySlash.

Rewrites <documentroot>/modules/dir/htaccess/.htaccess with various
DirectoryIndex settings and checks the served body / status, then DirectorySlash
redirect behaviour and the type->handler fallback cases.

Perl original used ``need_module 'dir'``.
"""

import os

import pytest

from apache_pytest import need_module, t_cmp

INDEX = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]
BAD_INDEX = ["foo", "goo", "moo", "bleh"]


def _htaccess_path(http):
    return os.path.join(http.vars("documentroot"), "modules", "dir", "htaccess",
                        ".htaccess")


def _write_htaccess(http, directive):
    with open(_htaccess_path(http), "w") as f:
        f.write("DirectoryIndex " + directive)


@need_module("dir")
def test_dir_directoryindex(http):
    url = "/modules/dir/htaccess/"
    forbidden_or_notfound = 403 if http.have_module("autoindex") else 404

    for bad in BAD_INDEX:
        # Bad index alone -> 403 (with autoindex) or 404.
        _write_htaccess(http, bad)
        assert http.GET_RC(url) == forbidden_or_notfound

        for idx in INDEX:
            expected = idx
            _write_htaccess(http, f"{idx}.html")
            assert http.GET_BODY(url) == expected

            _write_htaccess(http, f"{bad} {idx}.html")
            assert http.GET_BODY(url) == expected

            _write_htaccess(http, f"{idx}.html {bad}")
            assert http.GET_BODY(url) == expected

            _write_htaccess(http, f"/modules/alias/{idx}.html")
            assert http.GET_BODY(url) == expected

            _write_htaccess(http, f"{bad} /modules/alias/{idx}.html")
            assert http.GET_BODY(url) == expected

    # DirectoryIndex pointing at the alias index.
    _write_htaccess(http, "/modules/alias/index.html")
    assert http.GET_BODY(url).rstrip("\r\n") == "alias index"

    # All-bad index list -> 403/404.
    _write_htaccess(http, " ".join(BAD_INDEX))
    assert http.GET_RC(url) == forbidden_or_notfound

    expected = INDEX[0]
    index_html = [f"{i}.html" for i in INDEX]
    _write_htaccess(http, " ".join(index_html))
    assert http.GET_BODY(url) == expected

    _write_htaccess(http, " ".join(BAD_INDEX + index_html))
    assert http.GET_BODY(url) == expected

    # Remove .htaccess -> default index.html.
    os.unlink(_htaccess_path(http))
    assert http.GET_BODY(url).rstrip("\r\n") == "dir index"


@need_module("dir")
def test_dir_directoryslash(http):
    res = http.GET("/modules/dir", redirect_ok=False)
    assert res.status_code == 301
    res = http.GET("/modules/dir/htaccess", redirect_ok=False)
    assert res.status_code == 403


@need_module("dir")
def test_dir_directoryslash_notfound(http):
    if not http.have_min_apache_version("2.5.1"):
        pytest.skip("missing DirectorySlash NotFound")
    res = http.GET("/modules/dir/htaccess/sub", redirect_ok=False)
    assert res.status_code == 404


@need_module("dir")
def test_dir_fallback_handler(http):
    if not (http.have_min_apache_version("2.4.61")
            and http.have_module("mime") and http.have_module("status")):
        pytest.skip("doesn't work")
    body = http.GET_BODY("/modules/dir/fallback/")
    import re
    assert t_cmp(body, re.compile("Server Status")), "type->handler wasn't used"


@need_module("dir")
def test_dir_fallback_handler_multiviews(http):
    if not (http.have_min_apache_version("2.4.62")
            and http.have_module("negotiation") and http.have_module("status")):
        pytest.skip("doesn't work")
    body = http.GET_BODY("/modules/dir/fallback/fallback")
    import re
    assert t_cmp(body, re.compile("Server Status")), \
        "type->handler wasn't used w/ multiviews"
