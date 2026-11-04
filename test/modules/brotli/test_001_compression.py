import os

import pytest

from pyhttpd.conf import HttpdConf


class TestBrotliCompression:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            <Location "/">
                AddOutputFilterByType BROTLI_COMPRESS text/plain text/html text/css
            </Location>
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # Request a small text file with Accept-Encoding: br.
    # Verify Content-Encoding: br header is present.
    def test_brotli_001_01(self, env):
        url = env.mkurl("http", "test1", "/greeting.txt")
        r = env.curl_get(url, options=[
            "-H", "Accept-Encoding: br",
        ])
        assert r.response, "no response"
        assert r.response["status"] == 200
        assert r.response["header"].get("content-encoding") == "br", \
            f"expected Content-Encoding: br, got: {r.response['header']}"
        raw_body = r.response["body"]
        assert len(raw_body) > 0, "compressed body should not be empty"
        original = b"Good morning, fellow!"
        assert len(raw_body) != len(original) or raw_body != original, \
            "body should be compressed, not plain text"

    # Request a larger text file; verify brotli compression is applied.
    def test_brotli_001_02(self, env):
        url = env.mkurl("http", "test1", "/lorem.txt")
        r = env.curl_get(url, options=[
            "-H", "Accept-Encoding: br",
        ])
        assert r.response, "no response"
        assert r.response["status"] == 200
        assert r.response["header"].get("content-encoding") == "br", \
            f"expected Content-Encoding: br, got: {r.response['header']}"
        lorem_path = os.path.join(env.server_dir, "htdocs", "test1",
                                  "lorem.txt")
        orig_size = os.path.getsize(lorem_path)
        assert len(r.response["body"]) < orig_size, \
            "compressed response should be smaller than the original"

    # When the client does not advertise Accept-Encoding: br the response
    # must be served uncompressed -- no Content-Encoding header.
    def test_brotli_001_03(self, env):
        url = env.mkurl("http", "test1", "/greeting.txt")
        r = env.curl_get(url)
        assert r.response, "no response"
        assert r.response["status"] == 200
        assert "content-encoding" not in r.response["header"], \
            f"unexpected Content-Encoding present: " \
            f"{r.response['header'].get('content-encoding')}"
        body = r.response["body"].decode()
        assert body.strip() == "Good morning, fellow!"

    # Binary / non-matching content types must not be compressed.
    def test_brotli_001_04(self, env):
        bin_dir = os.path.join(env.server_dir, "htdocs", "test1")
        bin_path = os.path.join(bin_dir, "pixel.png")
        with open(bin_path, "wb") as f:
            f.write(
                b'\x89PNG\r\n\x1a\n'
                b'\x00\x00\x00\rIHDR\x00\x00\x00\x01'
                b'\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde'
                b'\x00\x00\x00\x0cIDATx'
                b'\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05'
                b'\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
            )
        url = env.mkurl("http", "test1", "/pixel.png")
        r = env.curl_get(url, options=[
            "-H", "Accept-Encoding: br",
        ])
        assert r.response, "no response"
        assert r.response["status"] == 200
        assert r.response["header"].get("content-encoding") != "br", \
            "binary content should not be brotli-compressed"
