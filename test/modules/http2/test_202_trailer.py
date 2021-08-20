import os
import pytest

from h2_conf import HttpdConf


def setup_data(env):
    s100 = "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678\n"
    with open(os.path.join(env.gen_dir, "data-1k"), 'w') as f:
        for i in range(10):
            f.write(s100)


# The trailer tests depend on "nghttp" as no other client seems to be able to send those
# rare things.
class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        setup_data(env)
        HttpdConf(env).add_vhost_cgi(h2proxy_self=True).install()
        assert env.apache_restart() == 0

    # check if the server survives a trailer or two
    def test_202_01(self, env):
        url = env.mkurl("https", "cgi", "/echo.py")
        fpath = os.path.join(env.gen_dir, "data-1k")
        r = env.nghttp().upload(url, fpath, options=["--trailer", "test: 1"])
        assert 300 > r.response["status"]
        assert 1000 == len(r.response["body"])

        r = env.nghttp().upload(url, fpath, options=["--trailer", "test: 1b", "--trailer", "XXX: test"])
        assert 300 > r.response["status"]
        assert 1000 == len(r.response["body"])

    # check if the server survives a trailer without content-length
    def test_202_02(self, env):
        url = env.mkurl("https", "cgi", "/echo.py")
        fpath = os.path.join(env.gen_dir, "data-1k")
        r = env.nghttp().upload(url, fpath, options=["--trailer", "test: 2", "--no-content-length"])
        assert 300 > r.response["status"]
        assert 1000 == len(r.response["body"])

    # check if echoing request headers in response from GET works
    def test_202_03(self, env):
        url = env.mkurl("https", "cgi", "/echohd.py?name=X")
        r = env.nghttp().get(url, options=["--header", "X: 3"])
        assert 300 > r.response["status"]
        assert b"X: 3\n" == r.response["body"]

    # check if echoing request headers in response from POST works
    def test_202_03b(self, env):
        url = env.mkurl("https", "cgi", "/echohd.py?name=X")
        r = env.nghttp().post_name(url, "Y", options=["--header", "X: 3b"])
        assert 300 > r.response["status"]
        assert b"X: 3b\n" == r.response["body"]

    # check if echoing request headers in response from POST works, but trailers are not seen
    # This is the way CGI invocation works.
    def test_202_04(self, env):
        url = env.mkurl("https", "cgi", "/echohd.py?name=X")
        r = env.nghttp().post_name(url, "Y", options=["--header", "X: 4a", "--trailer", "X: 4b"])
        assert 300 > r.response["status"]
        assert b"X: 4a\n" == r.response["body"]

    # The h2 status handler echoes a trailer if it sees a trailer
    def test_202_05(self, env):
        url = env.mkurl("https", "cgi", "/.well-known/h2/state")
        fpath = os.path.join(env.gen_dir, "data-1k")
        r = env.nghttp().upload(url, fpath, options=["--trailer", "test: 2"])
        assert 200 == r.response["status"]
        assert "1" == r.response["trailer"]["h2-trailers-in"]

    # Check that we can send and receive trailers throuh mod_proxy_http2
    def test_202_06(self, env):
        url = env.mkurl("https", "cgi", "/h2proxy/.well-known/h2/state")
        fpath = os.path.join(env.gen_dir, "data-1k")
        r = env.nghttp().upload(url, fpath, options=["--trailer", "test: 2"])
        assert 200 == r.response["status"]
        assert 'trailer' in r.response
        assert "1" == r.response['trailer']["h2-trailers-in"]
