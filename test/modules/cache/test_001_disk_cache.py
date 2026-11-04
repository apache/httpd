import os
import re
import shutil
import time

import pytest

from pyhttpd.conf import HttpdConf


class TestDiskCache:

    CACHE_EXPIRY = 4

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        cache_dir = os.path.join(env.gen_dir, "cache")
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
        os.makedirs(cache_dir, exist_ok=True)
        conf = HttpdConf(env, extras={
            f"cgi.{env.http_tld}": [
                f'CacheEnable disk /cache_time.py',
                f'CacheRoot "{cache_dir}"',
                f'CacheDefaultExpire {TestDiskCache.CACHE_EXPIRY}',
                f'CacheIgnoreNoLastMod On',
            ],
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0

    @staticmethod
    def _get_timestamp(env):
        url = env.mkurl("http", "cgi", "/cache_time.py")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        body = r.response["body"].decode("utf-8")
        m = re.search(r"time=(\S+)", body)
        assert m, f"Could not find time= in response body: {body}"
        return float(m.group(1))

    @staticmethod
    def _clear_cache(env):
        cache_dir = os.path.join(env.gen_dir, "cache")
        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)
        os.makedirs(cache_dir, exist_ok=True)

    def test_cache_001_01(self, env):
        """Cache hit: second request within expiry returns the same timestamp."""
        self._clear_cache(env)
        ts1 = self._get_timestamp(env)
        time.sleep(1)
        ts2 = self._get_timestamp(env)
        assert ts1 == ts2, (
            f"Expected cached response with same timestamp, "
            f"but got {ts1} and {ts2}"
        )

    def test_cache_001_02(self, env):
        """Cache expiry: request after expiry returns a new timestamp."""
        self._clear_cache(env)
        ts1 = self._get_timestamp(env)
        time.sleep(TestDiskCache.CACHE_EXPIRY + 1)
        ts2 = self._get_timestamp(env)
        assert ts1 != ts2, (
            f"Expected different timestamp after cache expiry, "
            f"but both were {ts1}"
        )

    def test_cache_001_03(self, env):
        """Cache disabled: requests always return different timestamps."""
        self._clear_cache(env)
        conf = HttpdConf(env, extras={
            f"cgi.{env.http_tld}": [
                f'CacheEnable disk /cache_time.py',
                f'CacheRoot "{env.gen_dir}/cache"',
                f'CacheDefaultExpire {TestDiskCache.CACHE_EXPIRY}',
                f'CacheIgnoreNoLastMod On',
                f'CacheDisable /cache_time.py',
            ],
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        ts1 = self._get_timestamp(env)
        time.sleep(1)
        ts2 = self._get_timestamp(env)
        assert ts1 != ts2, (
            f"Expected different timestamps with cache disabled, "
            f"but both were {ts1}"
        )
