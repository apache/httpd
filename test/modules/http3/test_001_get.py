import os

import pytest

from .env import H3Conf


class TestGet:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.make_data_file(os.path.join(env.server_docs_dir, "test1"),
                           "data-1m", 1024 * 1024)
        H3Conf(env).add_h3_vhosts().install()
        assert env.apache_restart() == 0

    # a static file is served over HTTP/3
    def test_h3_001_01(self, env):
        r = env.h3_get(env.mkurl("https", "test1", "/alive.json"))
        assert r.exit_code == 0, f"{r}"
        assert r.response["protocol"] == "HTTP/3"
        assert r.response["status"] == 200
        assert r.json["host"] == "test1"

    # the TLS port advertises HTTP/3 on the same port number
    def test_h3_001_02(self, env):
        r = env.curl_get(env.mkurl("https", "test1", "/alive.json"),
                         options=["--http1.1"])
        assert r.response["status"] == 200
        alt_svc = r.response["header"].get("alt-svc", "")
        assert alt_svc.startswith(f'h3=":{env.h3_port}"'), f"{r.response}"

    # a missing resource gives 404
    def test_h3_001_03(self, env):
        r = env.h3_get(env.mkurl("https", "test1", "/does-not-exist"))
        assert r.exit_code == 0, f"{r}"
        assert r.response["protocol"] == "HTTP/3"
        assert r.response["status"] == 404

    # HEAD gives the headers of a GET without the content
    def test_h3_001_04(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        r = env.h3_get(url, options=["-I"])
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        size = os.path.getsize(os.path.join(env.server_docs_dir,
                                            "test1", "index.html"))
        assert r.response["header"]["content-length"] == str(size)
        # curl -I prints the headers as the body; nothing else may follow
        assert r.response["body"].startswith(b"HTTP/3 200")
        assert b"<html" not in r.response["body"]

    # the Host header selects the virtual host, on the one QUIC listener
    def test_h3_001_05(self, env):
        r = env.h3_get(env.mkurl("https", "test2", "/alive.json"))
        assert r.exit_code == 0, f"{r}"
        assert r.response["protocol"] == "HTTP/3"
        assert r.json["host"] == "test2"

    # a 1 MB file arrives intact
    def test_h3_001_06(self, env):
        r = env.h3_get(env.mkurl("https", "test1", "/data-1m"))
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        with open(os.path.join(env.server_docs_dir, "test1", "data-1m"), "rb") as fd:
            assert r.response["body"] == fd.read()

    # several requests share one connection
    def test_h3_001_07(self, env):
        urls = [env.mkurl("https", "test1", "/alive.json") for _ in range(5)]
        r = env.curl_raw(urls, options=["--http3-only"])
        assert r.exit_code == 0, f"{r}"
        statuses = []
        resp = r.response
        while resp:
            statuses.append((resp["protocol"], resp["status"]))
            resp = resp.get("previous")
        assert statuses == [("HTTP/3", 200)] * 5
