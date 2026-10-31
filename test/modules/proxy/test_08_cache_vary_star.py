import os
import time
import uuid

import pytest

from pyhttpd.conf import HttpdConf
from .env import TCPFaker


# Backend answering /<run>/<index> with a body that depends on the request's
# Cookie, and a Cache-Control that makes the response otherwise cacheable.
class _IdentityFaker(TCPFaker):

    def __init__(self, host, port):
        super().__init__(host, port)
        self.hits = {}

    def _make_response(self, data):
        head = data.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
        path = head[0].split(" ")[1]
        self.hits[path] = self.hits.get(path, 0) + 1
        cookie = "anonymous"
        for line in head[1:]:
            if line.lower().startswith("cookie:"):
                cookie = line.split(":", 1)[1].strip()
        body = f"body-for-{cookie}\n"
        lines = ["HTTP/1.1 200 OK",
                 "Last-Modified: Thu, 01 Jan 2026 00:00:00 GMT",
                 'ETag: "t"',
                 "Cache-Control: public, max-age=60",
                 "Content-Type: text/plain",
                 f"Content-Length: {len(body)}",
                 "Connection: close"]
        return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


class TestCacheVaryStar:
    """BZ 70289: mod_cache's cacheability check for "Vary: *" only looked
    at r->headers_out, so a Vary: * set via "Header always" (which writes
    to r->err_headers_out) was missed by the check, while storage itself
    does merge err_headers_out in. This let a response meant for one
    client be stored and served back to a different client."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        faker = _IdentityFaker("127.0.0.1", env.http_port2)
        faker.start()
        cache_dir = os.path.join(env.gen_dir, "cache-vary-star")
        os.makedirs(cache_dir, exist_ok=True)

        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port,
                         doc_root="htdocs", with_ssl=False)
        conf.add([
            f'CacheRoot "{cache_dir}"',
            'CacheEnable disk "/cv/"',
            'CacheEnable disk "/cv2/"',
            'CacheEnable disk "/cv3/"',
            'CacheHeader on',
            '<Location "/cv/">',
            '    Header always set Vary "*"',
            '</Location>',
            '<Location "/cv3/">',
            '    Header set Vary "*"',
            '</Location>',
            f"ProxyPass /cv/ http://127.0.0.1:{env.http_port2}/",
            f"ProxyPass /cv2/ http://127.0.0.1:{env.http_port2}/",
            f"ProxyPass /cv3/ http://127.0.0.1:{env.http_port2}/",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        TestCacheVaryStar.faker = faker
        TestCacheVaryStar.run = uuid.uuid4().hex[:12]
        yield
        faker.stop()

    def get(self, env, path_prefix="/cv/", index=0, cookie=None):
        url = env.mkurl("http", "test1", f"{path_prefix}{self.run}/{index}")
        options = ["-H", f"Cookie: {cookie}"] if cookie else []
        r = env.curl_get(url, options=options)
        assert r.response["status"] == 200, f"{r}"
        return r.response

    def backend_hits(self, index=0):
        return self.faker.hits.get(f"/{self.run}/{index}", 0)

    # a victim's response must never be handed to another client under a
    # Vary: * header that was set via "Header always"
    def test_proxy_08_001(self, env):
        r1 = self.get(env, cookie="session=victim")
        assert r1["body"] == b"body-for-session=victim\n"
        # give the CACHE_SAVE filter's commit a moment to land, the same
        # way test_07_cache_control.py does for its own positive cases;
        # here it only matters because we are proving a negative.
        time.sleep(0.1)
        r2 = self.get(env)
        assert not r2["header"].get("x-cache", "").startswith("HIT"), \
            "Vary: * response (via Header always) was served from cache"
        assert r2["body"] == b"body-for-anonymous\n", \
            "victim's response body leaked to an anonymous request"
        assert self.backend_hits() == 2, "Vary: * response was stored"

    # positive control: the same disk cache setup, minus "Header always
    # set Vary *", does cache and serve a repeat request from disk. This
    # rules out test_proxy_08_001 passing merely because disk storage is
    # broken in this setup (e.g. a missing CacheRoot directory) rather
    # than because mod_cache correctly rejected the Vary: * response.
    def test_proxy_08_002(self, env):
        r1 = self.get(env, path_prefix="/cv2/", index=1)
        assert r1["body"] == b"body-for-anonymous\n"
        time.sleep(0.1)
        r2 = self.get(env, path_prefix="/cv2/", index=1)
        assert r2["header"]["x-cache"].startswith("HIT"), \
            "response without Vary: * was not served from the disk cache"
        assert r2["body"] == r1["body"]
        assert self.backend_hits(1) == 1, \
            "response without Vary: * was not cached"

    # a victim's response must never be handed to another client under a
    # Vary: * header set via plain "Header set" (which writes to
    # r->headers_out directly, the case the pre-fix code already checked)
    def test_proxy_08_003(self, env):
        r1 = self.get(env, path_prefix="/cv3/", index=2, cookie="session=victim")
        assert r1["body"] == b"body-for-session=victim\n"
        time.sleep(0.1)
        r2 = self.get(env, path_prefix="/cv3/", index=2)
        assert not r2["header"].get("x-cache", "").startswith("HIT"), \
            "Vary: * response (via headers_out) was served from cache"
        assert r2["body"] == b"body-for-anonymous\n", \
            "victim's response body leaked to an anonymous request"
        assert self.backend_hits(2) == 2, "Vary: * response was stored"
