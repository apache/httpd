"""Translated from t/modules/cache.t -- mod_cache (disk) quick test.

Selects the mod_cache vhost, ensures the disk cacheroot exists, then issues a
non-cached, a direct, and a cached request to index.html, each expecting 200.

Perl original used ``need 'cache', need_cache_disk,
need_min_apache_version('2.1.9')``. need_cache_disk additionally requires
mod_cache_disk; gated here with @need_module.
"""

import os

from apache_pytest import need_min_apache_version, need_module, t_cmp


@need_module("cache", "cache_disk")
@need_min_apache_version("2.1.9")
def test_cache(http):
    http.module("mod_cache")

    cacheroot = os.path.join(http.vars("statedir"), "cacheroot")
    os.makedirs(cacheroot, exist_ok=True)

    r = http.GET("/cache/")
    assert t_cmp(r.status_code, 200), "non-cached call to index.html"

    r = http.GET("/cache/index.html")
    assert t_cmp(r.status_code, 200), "call to cache index.html"

    r = http.GET("/cache/")
    assert t_cmp(r.status_code, 200), "cached call to index.html"
