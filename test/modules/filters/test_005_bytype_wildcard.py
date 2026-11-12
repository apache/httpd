import pytest

from pyhttpd.conf import HttpdConf


class TestByTypeWildcard:

    # The global test config already compresses text/html, text/plain,
    # text/xml and text/css, so only media-types not covered there are used.
    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
        <Location "/bytype/">
            AddType text/x-wild .tw .twc
            AddCharset utf-8 .twc
            AddType textual/x-wild .tl
            AddType application/x-wild .aw
            AddType application/x-exact .xw
            AddOutputFilterByType DEFLATE text/* application/x-exact
        </Location>
        """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize(["path", "ctype", "encoded"], [
        # wildcard matches any subtype of 'text'
        ["/bytype/001.tw", "text/x-wild", True],
        # wildcard matches with media-type parameters
        ["/bytype/002.twc", "text/x-wild; charset=utf-8", True],
        # wildcard must not match a type that merely starts with 'text'
        ["/bytype/003.tl", "textual/x-wild", False],
        # wildcard must not match a different type
        ["/bytype/004.aw", "application/x-wild", False],
        # exact media-types still match next to a wildcard
        ["/bytype/005.xw", "application/x-exact", True],
    ])
    def test_filters_005_01(self, env, path, ctype, encoded):
        url = env.mkurl("https", "test1", path)
        r = env.curl_get(url, options=["-H", "Accept-Encoding: gzip"])
        assert r.response["status"] == 200
        assert r.response["header"]["content-type"] == ctype
        if encoded:
            assert r.response["header"].get("content-encoding") == "gzip"
        else:
            assert "content-encoding" not in r.response["header"]
