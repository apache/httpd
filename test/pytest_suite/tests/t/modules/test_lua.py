r"""Translated from t/modules/lua.t -- mod_lua handlers.

mod_lua is not built locally, so these SKIP via @need_module("lua"). When the
module is present, each case GETs a Lua-handled URL and checks the response
code, body (exact string or regex), optional Content-Type, and optional
response headers.

Perl original: plan tests => 4 * scalar @ts, need 'lua';
"""

import re

import pytest

from apache_pytest import need_module, t_cmp


def _cases(http):
    version = http.vars("version") or ""
    scheme = http.vars("scheme")
    https = "yep" if scheme == "https" else "nope"
    hostport = http.hostport()
    pfx = "/modules/lua"
    return [
        {"url": f"{pfx}/hello.lua", "rcontent": "Hello Lua World!\n",
         "ctype": "text/plain"},
        {"url": f"{pfx}/404?translateme=1", "rcontent": "Hello Lua World!\n"},
        {"url": f"{pfx}/translate-inherit-before/404?translateme=1",
         "rcontent": "other lua handler\n"},
        {"url": f"{pfx}/translate-inherit-default-before/404?translateme=1",
         "rcontent": "other lua handler\n"},
        {"url": f"{pfx}/translate-inherit-after/404?translateme=1",
         "rcontent": "Hello Lua World!\n"},
        {"url": f"{pfx}/translate-inherit-before/404?translateme=1&ok=1",
         "rcontent": "other lua handler\n"},
        {"url": f"{pfx}/translate-inherit-default-before/404?translateme=1&ok=1",
         "rcontent": "other lua handler\n"},
        {"url": f"{pfx}/translate-inherit-after/404?translateme=1&ok=1",
         "rcontent": "other lua handler\n"},
        {"url": f"{pfx}/version.lua", "rcontent": re.compile("^" + re.escape(version))},
        {"url": f"{pfx}/method.lua", "rcontent": "GET"},
        {"url": f"{pfx}/201.lua", "rcontent": "", "code": 201},
        {"url": f"{pfx}/https.lua", "rcontent": https},
        {"url": f"{pfx}/setheaders.lua", "rcontent": "",
         "headers": {"X-Header": "yes", "X-Host": hostport}},
        {"url": f"{pfx}/setheaderfromparam.lua?HeaderName=foo&HeaderValue=bar",
         "rcontent": "Header set", "headers": {"foo": "bar"}},
        {"url": f"{pfx}/filtered/foobar.html",
         "rcontent": "prefix\nbucket:foobar\nsuffix\n"},
    ]


@need_module("lua")
def test_lua(http):
    for t in _cases(http):
        url = t["url"]
        r = http.GET(url)
        code = t.get("code", 200)
        assert t_cmp(r.status_code, code), f"code for {url}"
        assert t_cmp(r.text, t["rcontent"]), f"response content for {url}"

        if t.get("ctype"):
            assert t_cmp(r.headers.get("Content-Type"), t["ctype"]), f"c-type for {url}"

        headers = t.get("headers")
        if headers:
            for name, value in headers.items():
                actual = r.headers.get(name) or "<unset>"
                assert actual == value, (
                    f"'{name}' header value is '{actual}' (expected '{value}')")
