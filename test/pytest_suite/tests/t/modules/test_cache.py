"""Translated from t/modules/cache.t -- mod_cache (disk) quick test.

Selects the mod_cache vhost, ensures the disk cacheroot exists, then issues a
non-cached, a direct, and a cached request to index.html, each expecting 200.

Perl original used ``need 'cache', need_cache_disk,
need_min_apache_version('2.1.9')``. need_cache_disk additionally requires
mod_cache_disk; gated here with @need_module.
"""

import os
import shutil

from apache_pytest import need_min_apache_version, need_module, t_cmp


def _raw_get(http, path, headers=()):
    request = [
        f"GET {path} HTTP/1.1",
        f"Host: {http.hostport('mod_cache')}",
        "Connection: close",
    ]
    request.extend(f"{name}: {value}" for name, value in headers)

    with http.vhost_socket("mod_cache") as sock:
        sock.print("\r\n".join(request) + "\r\n\r\n")
        response = sock.read()

    head = response.split("\r\n\r\n", 1)[0].split("\r\n")
    fields = []
    for line in head[1:]:
        name, separator, value = line.partition(":")
        if separator:
            fields.append((name.lower(), value.lstrip()))
    return head[0], fields


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


@need_module("cache", "cache_disk", "headers")
@need_min_apache_version("2.1.9")
def test_cache_long_response_header(http):
    """A cache metadata line longer than MAX_STRING_LEN stays one header."""
    http.module("mod_cache")

    cacheroot = os.path.join(http.vars("statedir"), "cacheroot")
    shutil.rmtree(cacheroot, ignore_errors=True)
    os.makedirs(cacheroot, exist_ok=True)

    # Align a header-shaped tail with the old fixed-size read boundary.
    tail = "X-Cache-Tail: preserved"
    name = "TS" + "A" * (len(tail) - 4)
    first = "a" * 4000
    second = "b" * (8190 - len(first) - 2 - len(tail)) + tail
    expected = first + ", " + second

    status, prime = _raw_get(
        http,
        "/cache/index.html?long-response-header",
        ((name, first), (name, second)),
    )
    assert status.startswith("HTTP/1.1 200"), "cache prime returned 200"
    assert (name.lower(), expected) in prime, "prime response kept the long header"

    status, recalled = _raw_get(http, "/cache/index.html?long-response-header")
    assert status.startswith("HTTP/1.1 200"), "cached response returned 200"
    assert (name.lower(), expected) in recalled, "cache recall kept the long header"
    assert not any(name == "x-cache-tail" for name, _ in recalled), \
        "cache recall did not split a continuation chunk into another header"
