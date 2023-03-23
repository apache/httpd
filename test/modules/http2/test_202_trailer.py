import os
import pytest

from .env import H2Conf


def setup_data(env):
    s100 = "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678\n"
    with open(os.path.join(env.gen_dir, "data-1k"), 'w') as f:
        for i in range(10):
            f.write(s100)


# The trailer tests depend on "nghttp" as no other client seems to be able to send those
# rare things.
class TestTrailers:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        setup_data(env)
        conf = H2Conf(env, extras={
            f"cgi.{env.http_tld}": [
                "<Location \"/h2test/trailer\">",
                "  SetHandler h2test-trailer",
                "</Location>"
            ],
        })
        conf.add_vhost_cgi(h2proxy_self=True)
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

    # check if echoing request headers in response from POST works, but trailers are not seen
    # This is the way CGI invocation works.
    def test_h2_202_04(self, env):
        url = env.mkurl("https", "cgi", "/echohd.py?name=X")
        r = env.nghttp().post_name(url, "Y", options=["--header", "X: 4a", "--trailer", "X: 4b"])
        assert r.response["status"] < 300
        assert r.response["body"] == b"X: 4a\n"

    # check that our h2test-trailer handler works
    def test_h2_202_10(self, env):
        url = env.mkurl("https", "cgi", "/h2test/trailer?1024")
        r = env.nghttp().get(url)
        assert r.response["status"] == 200
        assert len(r.response["body"]) == 1024
        assert 'trailer' in r.response
        assert 'trailer-content-length' in r.response['trailer']
        assert r.response['trailer']['trailer-content-length'] == '1024'

    # check that trailers also for with empty bodies
    def test_h2_202_11(self, env):
        url = env.mkurl("https", "cgi", "/h2test/trailer?0")
        r = env.nghttp().get(url)
        assert r.response["status"] == 200
        assert len(r.response["body"]) == 0, f'{r.response["body"]}'
        assert 'trailer' in r.response
        assert 'trailer-content-length' in r.response['trailer']
        assert r.response['trailer']['trailer-content-length'] == '0'
