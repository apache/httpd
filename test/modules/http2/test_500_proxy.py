import inspect
import os
import re
import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestProxy:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add_vhost_cgi(proxy_self=True).install()
        assert env.apache_restart() == 0

    def local_src(self, fname):
        return os.path.join(os.path.dirname(inspect.getfile(TestProxy)), fname)

    def setup_method(self, method):
        print("setup_method: %s" % method.__name__)

    def teardown_method(self, method):
        print("teardown_method: %s" % method.__name__)

    def test_h2_500_01(self, env):
        url = env.mkurl("https", "cgi", "/proxy/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert "HTTP/1.1" == r.response["json"]["protocol"]
        assert r.response["json"]["https"] == ""
        assert r.response["json"]["ssl_protocol"] == ""
        assert r.response["json"]["h2"] == ""
        assert r.response["json"]["h2push"] == ""

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
        with open(self.local_src(fpath), mode='rb') as file:
            src = file.read()
        assert r2.response["body"] == src

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m",
    ])
    def test_h2_500_10(self, env, name, repeat):
        self.curl_upload_and_verify(env, name, ["--http2"])

    def test_h2_500_11(self, env):
        self.curl_upload_and_verify(env, "data-1k", [
            "--http1.1", "-H", "Content-Length:", "-H", "Transfer-Encoding: chunked"
        ])
        self.curl_upload_and_verify(env, "data-1k", ["--http2", "-H", "Content-Length:"])

    # POST some data using nghttp and see it echo'ed properly back
    def nghttp_post_and_verify(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/proxy/echo.py")
        fpath = os.path.join(env.gen_dir, fname)
        r = env.nghttp().upload(url, fpath, options=options)
        assert r.exit_code == 0
        assert 200 <= r.response["status"] < 300
        with open(self.local_src(fpath), mode='rb') as file:
            src = file.read()
        if r.response["body"] != src:
            with open(os.path.join(env.gen_dir, "nghttp.out"), 'w') as fd:
                fd.write(r.outraw.decode())
                fd.write("\nstderr:\n")
                fd.write(r.stderr)
            assert r.response["body"] == src

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m",
    ])
    def test_h2_500_20(self, env, name, repeat):
        self.nghttp_post_and_verify(env, name, [])

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m",
    ])
    def test_h2_500_21(self, env, name, repeat):
        self.nghttp_post_and_verify(env, name, ["--no-content-length"])

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
        with open(self.local_src(fpath), mode='rb') as file:
            src = file.read()
        assert src == r2.response["body"]

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m",
    ])
    def test_h2_500_22(self, env, name):
        self.nghttp_upload_and_verify(env, name, [])

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m",
    ])
    def test_h2_500_23(self, env, name):
        self.nghttp_upload_and_verify(env, name, ["--no-content-length"])

    # upload using nghttp and check returned status
    def nghttp_upload_stat(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/proxy/upload.py")
        fpath = os.path.join(env.gen_dir, fname)

        r = env.nghttp().upload_file(url, fpath, options=options)
        assert r.exit_code == 0
        assert 200 <= r.response["status"] < 300
        assert r.response["header"]["location"]

    def test_h2_500_24(self, env):
        for i in range(50):
            self.nghttp_upload_stat(env, "data-1k", ["--no-content-length"])

    # lets do some error tests
    def test_h2_500_30(self, env):
        url = env.mkurl("https", "cgi", "/proxy/h2test/error?status=500")
        r = env.curl_get(url)
        assert r.exit_code == 0, r
        assert r.response['status'] == 500
        url = env.mkurl("https", "cgi", "/proxy/h2test/error?error=timeout")
        r = env.curl_get(url)
        assert r.exit_code == 0, r
        assert r.response['status'] == 408

    # produce an error during response body
    def test_h2_500_31(self, env, repeat):
        url = env.mkurl("https", "cgi", "/proxy/h2test/error?body_error=timeout")
        r = env.curl_get(url)
        assert r.exit_code != 0, r
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH01110"   # Network error reading response
            ]
        )

    # produce an error, fail to generate an error bucket
    def test_h2_500_32(self, env, repeat):
        url = env.mkurl("https", "cgi", "/proxy/h2test/error?body_error=timeout&error_bucket=0")
        r = env.curl_get(url)
        assert r.exit_code != 0, r
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH01110"   # Network error reading response
            ]
        )
