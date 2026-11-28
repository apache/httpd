import os
import shutil

import pytest

from pyhttpd.conf import HttpdConf


class TestDiskCacheEmptyContentType:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        cache_dir = os.path.join(env.gen_dir, "cache-empty-ct")
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
        os.makedirs(cache_dir, exist_ok=True)
        conf = HttpdConf(env, extras={
            f"cgi.{env.http_tld}": [
                'CacheEnable disk /empty_ct.py',
                f'CacheRoot "{cache_dir}"',
                'CacheIgnoreNoLastMod On',
            ],
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0

    @staticmethod
    def _get_body(env):
        url = env.mkurl("http", "cgi", "/empty_ct.py")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        assert env.is_live()
        return r.response["body"]

    def test_cache_002_01_empty_ct_cached(self, env):
        """A response with an empty Content-Type is served, and the server
        survives caching it, without crashing."""
        body = self._get_body(env)
        assert b"time=" in body

    def test_cache_002_02_empty_ct_served_from_cache(self, env):
        """The stored entry is retrieved on the second request without
        crashing, and carries the body of the response that populated it."""
        body1 = self._get_body(env)
        body2 = self._get_body(env)
        assert body1 == body2, (
            f"Expected the cached response body, but got "
            f"{body1!r} and {body2!r}"
        )
