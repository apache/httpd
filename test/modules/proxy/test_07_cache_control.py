import os
import uuid

import pytest

from pyhttpd.conf import HttpdConf
from .env import TCPFaker


# Backend answering /<run>/<index> with the Cache-Control header lines of
# CASES[index], counting the requests it gets for every path.
class _CacheFaker(TCPFaker):

    def __init__(self, host, port, cases):
        super().__init__(host, port)
        self.cases = cases
        self.hits = {}

    def _make_response(self, data):
        head = data.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
        path = head[0].split(" ")[1]
        self.hits[path] = self.hits.get(path, 0) + 1
        cookie = ""
        for line in head[1:]:
            if line.lower().startswith("cookie:"):
                cookie = line.split(":", 1)[1].strip()
        cc, extra = self.cases[int(path.rsplit("/", 1)[1])]
        body = f"hit={self.hits[path]} cookie={cookie}\n"
        lines = ["HTTP/1.1 200 OK",
                 "Last-Modified: Thu, 01 Jan 2026 00:00:00 GMT",
                 'ETag: "t"',
                 "Content-Type: text/plain",
                 f"Content-Length: {len(body)}",
                 "Connection: close"]
        lines += [f"Cache-Control: {v}" for v in cc]
        lines += extra
        return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


# Cache-Control field lines and further response headers of the backend
NO_STORE = [
    [["no-store"], []],
    [["private"], []],
    [["private, no-store"], []],
    [["private,no-store,max-age=0"], []],
    [["private, no-store, max-age=0"], []],
    [["private , no-store , max-age=0"], []],
    [["max-age=60, private"], []],
    [["max-age=60, no-store"], []],
    [["no-store, max-age=60"], []],
    [["no-store, foo=bar"], []],
    [["foo=bar, no-store"], []],
    [["foo=\"a, b\", no-store"], []],
    [["private", "no-store", "max-age=0"], []],
]
STORED = [
    [["public, max-age=60"], []],
    [["max-age=60"], []],
    [["max-age=60, must-revalidate"], []],
    [["must-revalidate, max-age=60"], []],
    [["public, s-maxage=60"], []],
    [["max-age=60, stale-while-revalidate=30"], []],
    [["max-age=60, stale-if-error=30"], []],
    [["foo=\"a, b\", max-age=60"], []],
]
QUALIFIED = [
    [["max-age=60, private=\"X-Secret\""], []],
    [["max-age=60, private=\"X-Secret, Set-Cookie\""], []],
    [["max-age=60, no-cache=\"X-Secret,Set-Cookie\""], []],
]
USER = [
    [["private, no-store, max-age=0"], []],
]
CASES = NO_STORE + STORED + QUALIFIED + USER
for _c in QUALIFIED:
    _c[1] += ["Set-Cookie: a=b", "X-Secret: s", "X-Public: p"]


class TestCacheControl:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        faker = _CacheFaker("127.0.0.1", env.http_port2, CASES)
        faker.start()
        cache_dir = os.path.join(env.gen_dir, "cache-control")
        os.makedirs(cache_dir, exist_ok=True)

        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port,
                         doc_root="htdocs", with_ssl=False)
        conf.add([
            f'CacheRoot "{cache_dir}"',
            'CacheEnable disk "/cc/"',
            'CacheHeader on',
            'CacheStorePrivate Off',
            'CacheStoreNoStore Off',
            f"ProxyPass /cc/ http://127.0.0.1:{env.http_port2}/",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        TestCacheControl.faker = faker
        TestCacheControl.run = uuid.uuid4().hex[:12]
        yield
        faker.stop()

    def get(self, env, index, cookie=None):
        url = env.mkurl("http", "test1", f"/cc/{self.run}/{index}")
        options = ["-H", f"Cookie: {cookie}"] if cookie else []
        r = env.curl_get(url, options=options)
        assert r.response["status"] == 200, f"{r}"
        return r.response

    def backend_hits(self, index):
        return self.faker.hits.get(f"/{self.run}/{index}", 0)

    # a response that must not be stored is never served from the cache
    @pytest.mark.parametrize("index", range(len(NO_STORE)))
    def test_proxy_07_001(self, env, index):
        cc = ", ".join(CASES[index][0])
        r1 = self.get(env, index)
        r2 = self.get(env, index)
        assert self.backend_hits(index) == 2, f"Cache-Control: {cc} was cached"
        assert not r1["header"].get("x-cache", "").startswith("HIT")
        assert not r2["header"].get("x-cache", "").startswith("HIT")
        assert r2["body"] == b"hit=2 cookie=\n"

    # a response that may be stored is served from the cache
    @pytest.mark.parametrize("index", range(len(NO_STORE),
                                            len(NO_STORE) + len(STORED)))
    def test_proxy_07_002(self, env, index):
        cc = ", ".join(CASES[index][0])
        r1 = self.get(env, index)
        r2 = self.get(env, index)
        assert self.backend_hits(index) == 1, f"Cache-Control: {cc} not cached"
        assert r2["header"]["x-cache"].startswith("HIT")
        assert r2["body"] == r1["body"]

    # fields listed in private="..." and no-cache="..." are not stored,
    # whether one or several are listed, the rest of the response is
    @pytest.mark.parametrize("index", range(len(NO_STORE) + len(STORED),
                                            len(NO_STORE) + len(STORED) + len(QUALIFIED)))
    def test_proxy_07_003(self, env, index):
        cc = ", ".join(CASES[index][0])
        r1 = self.get(env, index)
        assert r1["header"]["x-secret"] == "s"
        assert r1["header"]["set-cookie"] == "a=b"
        r2 = self.get(env, index)
        assert self.backend_hits(index) == 1, f"Cache-Control: {cc} not cached"
        assert r2["header"]["x-cache"].startswith("HIT")
        assert r2["header"]["x-public"] == "p"
        assert "x-secret" not in r2["header"], f"X-Secret stored: {cc}"
        if "Set-Cookie" in cc:
            assert "set-cookie" not in r2["header"], f"Set-Cookie stored: {cc}"

    # a user specific response is not given to another request
    def test_proxy_07_004(self, env):
        index = len(CASES) - 1
        r1 = self.get(env, index, cookie="session=first")
        assert r1["body"] == b"hit=1 cookie=session=first\n"
        r2 = self.get(env, index)
        assert b"session=first" not in r2["body"]
        assert self.backend_hits(index) == 2
