import os
import re
import pytest

from .env import H2Conf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.setup_data_1k_1m()
        H2Conf(env).add_vhost_cgi(proxy_self=True).install()
        assert env.apache_restart() == 0

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    def test_h2_500_01(self, env):
        url = env.mkurl("https", "cgi", "/proxy/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert "HTTP/1.1" == r.response["json"]["protocol"]
        assert "" == r.response["json"]["https"]
        assert "" == r.response["json"]["ssl_protocol"]
        assert "" == r.response["json"]["h2"]
        assert "" == r.response["json"]["h2push"]

    # upload and GET again using curl, compare to original content
    def curl_upload_and_verify(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/proxy/upload.py")
        fpath = os.path.join(env.gen_dir, fname)
        r = env.curl_upload(url, fpath, options=options)
        assert r.exit_code == 0
        assert 200 <= r.response["status"] < 300

        # why is the scheme wrong?
        r2 = env.curl_get(re.sub(r'http:', 'https:', r.response["header"]["location"]))
        assert r2.exit_code == 0
        assert r2.response["status"] == 200
        with open(env.local_src(fpath), mode='rb') as file:
            src = file.read()
        assert src == r2.response["body"]

    def test_h2_500_10(self, env):
        self.curl_upload_and_verify(env, "data-1k", ["--http2"])
        self.curl_upload_and_verify(env, "data-10k", ["--http2"])
        self.curl_upload_and_verify(env, "data-100k", ["--http2"])
        self.curl_upload_and_verify(env, "data-1m", ["--http2"])

    # POST some data using nghttp and see it echo'ed properly back
    def nghttp_post_and_verify(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/proxy/echo.py")
        fpath = os.path.join(env.gen_dir, fname)
        r = env.nghttp().upload(url, fpath, options=options)
        assert r.exit_code == 0
        assert 200 <= r.response["status"] < 300
        with open(env.local_src(fpath), mode='rb') as file:
            src = file.read()
        assert src == r.response["body"]

    def test_h2_500_20(self, env):
        self.nghttp_post_and_verify(env, "data-1k", [])
        self.nghttp_post_and_verify(env, "data-10k", [])
        self.nghttp_post_and_verify(env, "data-100k", [])
        self.nghttp_post_and_verify(env, "data-1m", [])

    def test_h2_500_21(self, env):
        self.nghttp_post_and_verify(env, "data-1k", ["--no-content-length"])
        self.nghttp_post_and_verify(env, "data-10k", ["--no-content-length"])
        self.nghttp_post_and_verify(env, "data-100k", ["--no-content-length"])
        self.nghttp_post_and_verify(env, "data-1m", ["--no-content-length"])

    # upload and GET again using nghttp, compare to original content
    def nghttp_upload_and_verify(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/proxy/upload.py")
        fpath = os.path.join(env.gen_dir, fname)

        r = env.nghttp().upload_file(url, fpath, options=options)
        assert r.exit_code == 0
        assert 200 <= r.response["status"] < 300
        assert r.response["header"]["location"]

        # why is the scheme wrong?
        r2 = env.nghttp().get(re.sub(r'http:', 'https:', r.response["header"]["location"]))
        assert r2.exit_code == 0
        assert r2.response["status"] == 200
        with open(env.local_src(fpath), mode='rb') as file:
            src = file.read()
        assert src == r2.response["body"]

    def test_h2_500_22(self, env):
        self.nghttp_upload_and_verify(env, "data-1k", [])
        self.nghttp_upload_and_verify(env, "data-10k", [])
        self.nghttp_upload_and_verify(env, "data-100k", [])
        self.nghttp_upload_and_verify(env, "data-1m", [])

    def test_h2_500_23(self, env):
        self.nghttp_upload_and_verify(env, "data-1k", ["--no-content-length"])
        self.nghttp_upload_and_verify(env, "data-10k", ["--no-content-length"])
        self.nghttp_upload_and_verify(env, "data-100k", ["--no-content-length"])
        self.nghttp_upload_and_verify(env, "data-1m", ["--no-content-length"])

    # upload using nghttp and check returned status
    def nghttp_upload_stat(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/proxy/upload.py")
        fpath = os.path.join(env.gen_dir, fname)

        r = env.nghttp().upload_file(url, fpath, options=options)
        assert r.exit_code == 0
        assert 200 <= r.response["status"] < 300
        assert r.response["header"]["location"]

    def test_h2_500_24(self, env):
        for i in range(100):
            self.nghttp_upload_stat(env, "data-1k", ["--no-content-length"])
