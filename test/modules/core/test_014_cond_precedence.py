"""If-None-Match/If-Match must take precedence over the date-based
conditional headers they are paired with (RFC 9110 13.1.3/13.1.4).

ap_meets_conditions() (modules/http/http_protocol.c) evaluated all four
conditional request headers independently: If-Unmodified-Since was
checked even when an If-Match header was already present, and
If-Modified-Since was checked even when an If-None-Match header was
already present. RFC 9110 requires the opposite: a recipient MUST
ignore If-Modified-Since when If-None-Match is present, and MUST
ignore If-Unmodified-Since when If-Match is present, since the
entity-tag comparison is considered the more accurate condition (the
two are only combined for interoperating with older intermediaries
that predate entity tags). PR 70310.
"""

import pytest

from pyhttpd.conf import HttpdConf


class TestCondPrecedence:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        HttpdConf(env).install()
        assert env.apache_restart() == 0

    def url(self, env):
        return env.mkurl("http", "core", "/condreq/data.txt")

    def etag_and_lastmod(self, env):
        r = env.curl_get(self.url(env))
        assert r.response["status"] == 200, f"{r}"
        return r.response["header"]["etag"], r.response["header"]["last-modified"]

    def test_core_014_01_if_none_match_wins_over_stale_if_modified_since(self, env):
        etag, _ = self.etag_and_lastmod(env)
        # The ETag matches (If-None-Match succeeds, a 304 on its own), but
        # If-Modified-Since carries an old date the resource "looks modified
        # since" in isolation. If-Modified-Since must be ignored because
        # If-None-Match is present: the response must still be 304.
        r = env.curl_get(self.url(env), options=[
            "-H", f"If-None-Match: {etag}",
            "-H", "If-Modified-Since: Fri, 01 Jan 2010 00:00:00 GMT",
        ])
        assert r.response["status"] == 304, \
            f"expected 304 (If-Modified-Since must be ignored next to a " \
            f"matching If-None-Match), got {r.response['status']}"

    def test_core_014_02_if_match_wins_over_stale_if_unmodified_since(self, env):
        # If-Match: * always succeeds; If-Unmodified-Since carries a date
        # older than the resource's real Last-Modified, which would fail
        # the condition in isolation. If-Unmodified-Since must be ignored
        # because If-Match is present: the response must still be 200.
        r = env.curl_get(self.url(env), options=[
            "-H", "If-Match: *",
            "-H", "If-Unmodified-Since: Sat, 01 Jan 2000 00:00:00 GMT",
        ])
        assert r.response["status"] == 200, \
            f"expected 200 (If-Unmodified-Since must be ignored next to a " \
            f"satisfied If-Match), got {r.response['status']}"

    def test_core_014_03_if_modified_since_alone_still_applies(self, env):
        # Sanity: without If-None-Match, a stale If-Modified-Since on its
        # own still behaves as before (not touched by this change).
        r = env.curl_get(self.url(env), options=[
            "-H", "If-Modified-Since: Fri, 01 Jan 2010 00:00:00 GMT",
        ])
        assert r.response["status"] == 200

    def test_core_014_04_if_unmodified_since_alone_still_applies(self, env):
        # Sanity: without If-Match, a stale If-Unmodified-Since on its own
        # still fails the precondition as before (not touched by this
        # change).
        r = env.curl_get(self.url(env), options=[
            "-H", "If-Unmodified-Since: Sat, 01 Jan 2000 00:00:00 GMT",
        ])
        assert r.response["status"] == 412
