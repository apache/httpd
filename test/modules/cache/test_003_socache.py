import pytest

from pyhttpd.conf import HttpdConf


class TestCacheSocache:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            f"cgi.{env.http_tld}": [
                'CacheSocache shmcb',
                'CacheSocacheMaxSize 102400',
                'CacheEnable socache /socache_body.py',
            ],
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0

    @staticmethod
    def _get_body(env):
        # An empty Cache-Control field line in the request, an edge case
        # that formerly triggered out-of-bounds reads.
        url = env.mkurl("http", "cgi", "/socache_body.py")
        r = env.curl_get(url, options=["-H", "Cache-Control:"])
        assert r.response["status"] == 200
        assert env.is_live()
        return r.response["body"]

    def test_cache_003_01_socache_populate(self, env):
        """A cacheable response is served through mod_cache_socache, and the
        server survives storing it, without crashing."""
        body = self._get_body(env)
        assert b"time=" in body

    def test_cache_003_02_socache_retrieve(self, env):
        """The stored entry is retrieved on the second request without
        crashing, and carries the body of the response that populated it."""
        body1 = self._get_body(env)
        body2 = self._get_body(env)
        assert body1 == body2, (
            f"Expected the cached response body, but got "
            f"{body1!r} and {body2!r}"
        )
        env.httpd_error_log.ignore_recent()
