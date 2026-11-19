"""Cache key must vary with the raw Host a reverse-proxied backend sees.

mod_cache's quick-handler/CACHE_SAVE key for a non-forward-proxy request is
built from the vhost's canonical name (ap_get_server_name()), not from the
Host header the client actually sent. With ProxyPreserveHost On (or the
X-Forwarded-Host it implies), the backend sees that raw, unnormalized Host
instead, and can vary its response by it (e.g. echo it into a redirect
Location or a generated link). Two Host spellings that both route to the
same vhost (case, a trailing dot, an explicit default port) then collapse
onto the one cache entry despite the backend answering them differently,
so a response generated for one Host spelling is served to a request
carrying another (PR 70029).
"""

import os
import uuid

import pytest

from pyhttpd.conf import HttpdConf
from .env import TCPFaker


class _HostEchoFaker(TCPFaker):
    """Backend answering /<run>/<path> with the Host header it received,
    cacheable, and counting how many times it was actually hit per path.
    """

    def __init__(self, host, port):
        super().__init__(host, port)
        self.hits = {}
        self.last_host = {}

    def _make_response(self, data):
        head = data.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
        path = head[0].split(" ")[1]
        host = ""
        for line in head[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
        self.hits[path] = self.hits.get(path, 0) + 1
        self.last_host[path] = host
        body = f"host={host} hit={self.hits[path]}\n"
        lines = ["HTTP/1.1 200 OK",
                 "Last-Modified: Thu, 01 Jan 2026 00:00:00 GMT",
                 'ETag: "t"',
                 "Content-Type: text/plain",
                 f"Content-Length: {len(body)}",
                 "Cache-Control: public, max-age=60",
                 "Connection: close"]
        return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


class TestCacheHostKey:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        faker = _HostEchoFaker("127.0.0.1", env.http_port2)
        faker.start()
        cache_dir = os.path.join(env.gen_dir, "cache-host-key")
        os.makedirs(cache_dir, exist_ok=True)

        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port,
                         doc_root="htdocs", with_ssl=False)
        conf.add([
            f'CacheRoot "{cache_dir}"',
            'CacheEnable disk "/hostkey/"',
            'CacheHeader on',
            'ProxyPreserveHost On',
            f"ProxyPass /hostkey/ http://127.0.0.1:{env.http_port2}/",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        TestCacheHostKey.faker = faker
        TestCacheHostKey.run = uuid.uuid4().hex[:12]
        yield
        faker.stop()

    def get(self, env, host_header):
        url = env.mkurl("http", "test1", f"/hostkey/{self.run}/same")
        r = env.curl_get(url, options=["-H", f"Host: {host_header}"])
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200, f"{r}"
        return r.response

    def backend_hits(self):
        return self.faker.hits.get(f"/{self.run}/same", 0)

    def test_proxy_08_001_trailing_dot_does_not_collide_with_bare_host(self, env):
        bare = f"test1.{env.http_tld}"
        dotted = bare + "."

        r1 = self.get(env, dotted)
        assert r1["body"] == f"host={dotted} hit=1\n".encode()
        assert self.backend_hits() == 1

        r2 = self.get(env, bare)
        # Each Host spelling must get its own, backend-generated answer: a
        # cache hit here would mean this request got the body the backend
        # produced for the *other* Host, "test1.{tld}.".
        assert not r2["header"].get("x-cache", "").startswith("HIT"), \
            f"request for Host: {bare} was served the cache entry for " \
            f"Host: {dotted}"
        assert r2["body"] == f"host={bare} hit=2\n".encode()
        assert self.backend_hits() == 2

    def test_proxy_08_002_same_host_is_still_cached(self, env):
        host = f"test1.{env.http_tld}"
        self.run = uuid.uuid4().hex[:12]
        r1 = self.get(env, host)
        assert self.backend_hits() == 1
        r2 = self.get(env, host)
        assert r2["header"]["x-cache"].startswith("HIT")
        assert r2["body"] == r1["body"]
        assert self.backend_hits() == 1
