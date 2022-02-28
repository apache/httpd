import os
import pytest

from .env import H2Conf, H2TestEnv


# The trailer tests depend on "nghttp" as no other client seems to be able to send those
# rare things.
@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestTrailers:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env)
        conf.add_vhost_cgi(h2proxy_self=True, proxy_self=True)
        conf.add("LogLevel http1:trace4 http:trace4 http2:trace4")
        conf.install()
        assert env.apache_restart() == 0

    # check if the server survives a trailer or two
    def test_h2_202_01(self, env):
        url = env.mkurl("https", "cgi", "/echo.py")
        fpath = os.path.join(env.gen_dir, "data-1k")
        r = env.nghttp().upload(url, fpath, options=["--trailer", "test: 1"])
        assert r.response["status"] < 300
        assert len(r.response["body"]) == 1000

        r = env.nghttp().upload(url, fpath, options=["--trailer", "test: 1b", "--trailer", "XXX: test"])
        assert r.response["status"] < 300
        assert len(r.response["body"]) == 1000

    # check if the server survives a trailer without content-length
    def test_h2_202_02(self, env):
        url = env.mkurl("https", "cgi", "/echo.py")
        fpath = os.path.join(env.gen_dir, "data-1k")
        r = env.nghttp().upload(url, fpath, options=["--trailer", "test: 2", "--no-content-length"])
        assert r.response["status"] < 300
        assert len(r.response["body"]) == 1000

    # check if echoing request headers in response from GET works
    def test_h2_202_03(self, env):
        url = env.mkurl("https", "cgi", "/echohd.py?name=X")
        r = env.nghttp().get(url, options=["--header", "X: 3"])
        assert r.response["status"] < 300
        assert r.response["body"] == b"X: 3\n"

    # check if echoing request headers in response from POST works
    def test_h2_202_03b(self, env):
        url = env.mkurl("https", "cgi", "/echohd.py?name=X")
        r = env.nghttp().post_name(url, "Y", options=["--header", "X: 3b"])
        assert r.response["status"] < 300
        assert r.response["body"] == b"X: 3b\n"

    # check if echoing request headers in response from POST works,
    # but trailers are not seen. This is the way CGI invocation works.
    def test_h2_202_04(self, env):
        url = env.mkurl("https", "cgi", "/echohd.py?name=X")
        r = env.nghttp().post_name(url, "Y", options=["--header", "X: 4a", "--trailer", "X: 4b"])
        assert r.response["status"] < 300
        assert r.response["body"] == b"X: 4a\n"

    # check that we get trailers out when sending some in
    def test_h2_202_05(self, env):
        url = env.mkurl("https", "cgi", "/h2test/echo")
        fpath = os.path.join(env.gen_dir, "data-1k")
        r = env.nghttp().upload(url, fpath, options=["--trailer", "test: 5"])
        assert r.response["status"] < 300
        assert len(r.response["body"]) == 1000
        assert r.response["trailer"]["h2test-trailers-in"] == "1"

    # check that we get trailers out when sending some in, no c-l
    def test_h2_202_06(self, env):
        url = env.mkurl("https", "cgi", "/h2test/echo")
        fpath = os.path.join(env.gen_dir, "data-1k")
        r = env.nghttp().upload(url, fpath, options=["--trailer", "test: 6", "--no-content-length"])
        assert r.response["status"] < 300
        assert len(r.response["body"]) == 1000
        assert r.response["trailer"]["h2test-trailers-in"] == "1"

    # check that we get trailers out though h1 proxy
    def test_h2_202_07(self, env):
        url = env.mkurl("https", "cgi", "/proxy/h2test/echo")
        fpath = os.path.join(env.gen_dir, "data-1k")
        r = env.nghttp().upload(url, fpath, options=["--trailer", "test: 6"])
        assert r.response["status"] < 300
        assert len(r.response["body"]) == 1000
        assert r.response["trailer"]["h2test-trailers-in"] == "1"

    # check that we get trailers out though h2 proxy
    def test_h2_202_08(self, env):
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/echo")
        fpath = os.path.join(env.gen_dir, "data-1k")
        r = env.nghttp().upload(url, fpath, options=["--trailer", "test: 6"])
        assert r.response["status"] < 300
        assert len(r.response["body"]) == 1000
        assert r.response["trailer"]["h2test-trailers-in"] == "1"
