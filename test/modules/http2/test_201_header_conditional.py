import pytest

from h2_conf import HttpdConf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        HttpdConf(env).add(
            """
            KeepAlive on
            MaxKeepAliveRequests 30
            KeepAliveTimeout 30"""
        ).add_vhost_test1().install()
        assert env.apache_restart() == 0

    # check handling of 'if-modified-since' header
    def test_201_01(self, env):
        url = env.mkurl("https", "test1", "/006/006.css")
        r = env.curl_get(url)
        assert 200 == r.response["status"]
        lm = r.response["header"]["last-modified"]
        assert lm
        r = env.curl_get(url, options=["-H", "if-modified-since: %s" % lm])
        assert 304 == r.response["status"]
        r = env.curl_get(url, options=["-H", "if-modified-since: Tue, 04 Sep 2010 11:51:59 GMT"])
        assert 200 == r.response["status"]

    # check handling of 'if-none-match' header
    def test_201_02(self, env):
        url = env.mkurl("https", "test1", "/006/006.css")
        r = env.curl_get(url)
        assert 200 == r.response["status"]
        etag = r.response["header"]["etag"]
        assert etag
        r = env.curl_get(url, options=["-H", "if-none-match: %s" % etag])
        assert 304 == r.response["status"]
        r = env.curl_get(url, options=["-H", "if-none-match: dummy"])
        assert 200 == r.response["status"]
        
    @pytest.mark.skipif(True, reason="304 misses the Vary header in trunk and 2.4.x")
    def test_201_03(self, env):
        url = env.mkurl("https", "test1", "/006.html")
        r = env.curl_get(url, options=["-H", "Accept-Encoding: gzip"])
        assert 200 == r.response["status"]
        for h in r.response["header"]:
            print("%s: %s" % (h, r.response["header"][h]))
        lm = r.response["header"]["last-modified"]
        assert lm
        assert "gzip" == r.response["header"]["content-encoding"]
        assert "Accept-Encoding" in r.response["header"]["vary"]
        
        r = env.curl_get(url, options=["-H", "if-modified-since: %s" % lm,
                                       "-H", "Accept-Encoding: gzip"])
        assert 304 == r.response["status"]
        for h in r.response["header"]:
            print("%s: %s" % (h, r.response["header"][h]))
        assert "vary" in r.response["header"]

    # Check if "Keep-Alive" response header is removed in HTTP/2.
    def test_201_04(self, env):
        url = env.mkurl("https", "test1", "/006.html")
        r = env.curl_get(url, options=["--http1.1", "-H", "Connection: keep-alive"])
        assert 200 == r.response["status"]
        assert "timeout=30, max=30" == r.response["header"]["keep-alive"]
        r = env.curl_get(url, options=["-H", "Connection: keep-alive"])
        assert 200 == r.response["status"]
        assert "keep-alive" not in r.response["header"]
