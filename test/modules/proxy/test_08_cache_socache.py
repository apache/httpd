import os
import time
import uuid

import pytest

from pyhttpd.conf import HttpdConf
from .env import TCPFaker

# Size limit of one cache entry, headers and body together
MAX_ENTRY = 8192


# Backend answering /<run>/<index> with a body of SIZES[index] bytes made of
# the X-Var request header, or with 304 when the request is conditional on
# the entity tag. The 304 carries "pad" bytes of additional header fields.
class _RevalidateFaker(TCPFaker):

    def __init__(self, host, port, sizes):
        super().__init__(host, port)
        self.sizes = sizes
        self.hits = {}
        self.conditional = {}
        self.pad = 0

    def _make_response(self, data):
        head = data.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
        path = head[0].split(" ")[1]
        fields = {}
        for line in head[1:]:
            name, _, value = line.partition(":")
            fields[name.lower()] = value.strip()
        variant = fields.get("x-var", "")
        key = (path, variant)
        validators = ["Last-Modified: Thu, 01 Jan 2026 00:00:00 GMT",
                      f'ETag: "t-{variant}"',
                      "Cache-Control: max-age=1",
                      "Vary: X-Var",
                      "Connection: close"]
        if fields.get("if-none-match") == f'"t-{variant}"':
            self.conditional[key] = self.conditional.get(key, 0) + 1
            pad = [f"X-Pad{i}: {'p' * 3000}" for i in range(self.pad // 3000)]
            return ("\r\n".join(["HTTP/1.1 304 Not Modified"] + validators + pad)
                    + "\r\n\r\n").encode()
        self.hits[key] = self.hits.get(key, 0) + 1
        body = (variant or "x") * self.sizes[int(path.rsplit("/", 1)[1])]
        lines = ["HTTP/1.1 200 OK",
                 "Content-Type: application/octet-stream",
                 f"Content-Length: {len(body)}"] + validators
        return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


SIZES = [284, 0, 700, 1100, 3000]


class TestCacheSocache:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        faker = _RevalidateFaker("127.0.0.1", env.http_port2, SIZES)
        faker.start()
        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port,
                         doc_root="htdocs", with_ssl=False)
        conf.add([
            f'CacheSocache shmcb:{os.path.join(env.gen_dir, "socache")}(512000)',
            f'CacheSocacheMaxSize {MAX_ENTRY}',
            'CacheEnable socache "/sc/"',
            'CacheHeader on',
            f"ProxyPass /sc/ http://127.0.0.1:{env.http_port2}/",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        TestCacheSocache.faker = faker
        TestCacheSocache.run = uuid.uuid4().hex[:12]
        yield
        faker.stop()

    def get(self, env, index, variant=None):
        url = env.mkurl("http", "test1", f"/sc/{self.run}/{index}")
        options = ["-H", f"X-Var: {variant}"] if variant else []
        r = env.curl_get(url, options=options)
        assert r.response["status"] == 200, f"{r}"
        return r.response

    def body(self, index, variant=None):
        return ((variant or "x") * SIZES[index]).encode()

    def conditional(self, index, variant=None):
        return self.faker.conditional.get((f"/{self.run}/{index}", variant or ""), 0)

    def backend_hits(self, index, variant=None):
        return self.faker.hits.get((f"/{self.run}/{index}", variant or ""), 0)

    # the body is kept in the cache when the headers are refreshed by a 304
    @pytest.mark.parametrize("index", [0, 1])
    def test_proxy_08_001(self, env, index):
        assert self.get(env, index)["body"] == self.body(index)
        time.sleep(2)
        assert self.get(env, index)["body"] == self.body(index)
        assert self.conditional(index) == 1, "entry was not revalidated"
        r = self.get(env, index)
        assert r["header"]["x-cache"].startswith("HIT")
        assert r["body"] == self.body(index)

    # every variant keeps its own body when it is revalidated
    def test_proxy_08_002(self, env):
        index = 2
        for variant in ["a", "b"]:
            assert self.get(env, index, variant)["body"] == self.body(index, variant)
        time.sleep(2)
        for variant in ["a", "b"]:
            assert self.get(env, index, variant)["body"] == self.body(index, variant)
            assert self.conditional(index, variant) == 1
        for variant in ["a", "b"]:
            r = self.get(env, index, variant)
            assert r["header"]["x-cache"].startswith("HIT")
            assert r["body"] == self.body(index, variant)

    # the body survives any number of revalidations
    def test_proxy_08_003(self, env):
        index = 3
        assert self.get(env, index)["body"] == self.body(index)
        for n in range(1, 4):
            time.sleep(2)
            assert self.get(env, index)["body"] == self.body(index)
            assert self.conditional(index) == n
            r = self.get(env, index)
            assert r["header"]["x-cache"].startswith("HIT")
            assert r["body"] == self.body(index)
        assert self.backend_hits(index) == 1

    # a refreshed entry that no longer fits is dropped, not stored truncated
    def test_proxy_08_004(self, env):
        index = 4
        assert self.get(env, index)["body"] == self.body(index)
        time.sleep(2)
        self.faker.pad = 2 * 3000
        try:
            r = self.get(env, index)
        finally:
            self.faker.pad = 0
        assert self.conditional(index) == 1
        assert r["body"] == self.body(index)
        r = self.get(env, index)
        assert not r["header"]["x-cache"].startswith("HIT")
        assert r["body"] == self.body(index)
        assert self.backend_hits(index) == 2
        r = self.get(env, index)
        assert r["header"]["x-cache"].startswith("HIT")
        assert r["body"] == self.body(index)
