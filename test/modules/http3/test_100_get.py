import gzip
import os

import pytest

from .env import H3Conf, DATA_SIZES, data_bytes


class TestGet:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost(directives=[
            "<Location /hop>",
            "  Header always set Keep-Alive timeout=5",
            "  Header always set Upgrade h2c",
            "  Header always set X-Hop 1",
            "  Header always set Connection X-Hop",
            "</Location>",
        ]).install()
        assert env.apache_restart() == 0

    def test_h3_100_01_index(self, env):
        r = env.h3_client().get("/")
        assert r.status == 200, f"{r}"
        with open(os.path.join(env.server_docs_dir, "test1", "index.html"), "rb") as fd:
            assert r.body == fd.read()
        assert r.header("content-type") == "text/html"
        assert r.header("content-length") == str(len(r.body))

    @pytest.mark.parametrize("name", list(DATA_SIZES))
    def test_h3_100_02_sizes(self, env, name):
        r = env.h3_client(timeout=30).get(f"/{name}")
        assert r.status == 200, f"{r}"
        assert r.header("content-length") == str(DATA_SIZES[name])
        assert r.body == data_bytes(DATA_SIZES[name])

    def test_h3_100_03_head(self, env):
        r = env.h3_client().request("HEAD", "/h3data-1m")
        assert r.status == 200, f"{r}"
        assert r.header("content-length") == str(DATA_SIZES["h3data-1m"])
        assert r.body == b""

    def test_h3_100_04_not_found(self, env):
        r = env.h3_client().get("/does-not-exist")
        assert r.status == 404, f"{r}"
        assert b"Not Found" in r.body

    def test_h3_100_05_conditional(self, env):
        client = env.h3_client()
        r = client.get("/h3data-1k")
        assert r.status == 200, f"{r}"
        etag = r.header("etag")
        last_modified = r.header("last-modified")
        assert etag and last_modified
        r = client.get("/h3data-1k", headers=[("if-none-match", etag)])
        assert r.status == 304, f"{r}"
        assert r.body == b""
        r = client.get("/h3data-1k", headers=[("if-modified-since", last_modified)])
        assert r.status == 304, f"{r}"

    def test_h3_100_06_range(self, env):
        r = env.h3_client().get("/h3data-100k", headers=[("range", "bytes=100-199")])
        assert r.status == 206, f"{r}"
        assert r.header("content-range") == f"bytes 100-199/{DATA_SIZES['h3data-100k']}"
        assert r.body == data_bytes(DATA_SIZES["h3data-100k"])[100:200]

    def test_h3_100_07_multi_range(self, env):
        r = env.h3_client().get("/h3data-100k",
                                headers=[("range", "bytes=0-9,1000-1009")])
        assert r.status == 206, f"{r}"
        assert r.header("content-type").startswith("multipart/byteranges")
        data = data_bytes(DATA_SIZES["h3data-100k"])
        assert data[0:10] in r.body and data[1000:1010] in r.body

    def test_h3_100_08_sequential(self, env):
        rs = env.h3_client().requests([dict(path="/h3data-1k")] * 50,
                                      sequential=True)
        assert [r.status for r in rs] == [200] * 50
        assert all(r.body == data_bytes(1024) for r in rs)

    def test_h3_100_09_concurrent(self, env):
        rs = env.h3_client(timeout=30).requests([dict(path="/h3data-100k")] * 20)
        assert [r.status for r in rs] == [200] * 20, f"{rs}"
        expected = data_bytes(DATA_SIZES["h3data-100k"])
        assert all(r.body == expected for r in rs)

    def test_h3_100_10_hop_by_hop(self, env):
        r = env.curl_get(f"https://{env.h3_domain}:{env.https_port}/hop/",
                         options=["--http1.1"])
        assert "x-hop" in r.response["header"], f"{r.response}"
        r = env.h3_client().get("/hop/")
        assert r.status in (200, 404), f"{r}"
        names = {k.decode() for k, _ in r.headers}
        assert not names & {"connection", "keep-alive", "upgrade", "x-hop",
                            "transfer-encoding"}, f"{r.headers}"

    def test_h3_100_11_gzip(self, env):
        r = env.h3_client().get("/", headers=[("accept-encoding", "gzip")])
        assert r.status == 200, f"{r}"
        assert r.header("content-encoding") == "gzip"
        assert "Accept-Encoding" in r.header("vary")
        with open(os.path.join(env.server_docs_dir, "test1", "index.html"), "rb") as fd:
            assert gzip.decompress(r.body) == fd.read()
