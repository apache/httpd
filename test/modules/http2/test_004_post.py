import difflib
import email.parser
import inspect
import json
import os
import re
import sys

import pytest

from .env import H2Conf


class TestPost:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        TestPost._local_dir = os.path.dirname(inspect.getfile(TestPost))
        H2Conf(env).add_vhost_cgi().install()
        assert env.apache_restart() == 0

    def local_src(self, fname):
        return os.path.join(TestPost._local_dir, fname)

    # upload and GET again using curl, compare to original content
    def curl_upload_and_verify(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/upload.py")
        fpath = os.path.join(env.gen_dir, fname)
        r = env.curl_upload(url, fpath, options=options)
        assert r.exit_code == 0, f"{r}"
        assert 200 <= r.response["status"] < 300

        r2 = env.curl_get(r.response["header"]["location"])
        assert r2.exit_code == 0
        assert r2.response["status"] == 200
        with open(self.local_src(fpath), mode='rb') as file:
            src = file.read()
        assert src == r2.response["body"]

    def test_h2_004_01(self, env):
        self.curl_upload_and_verify(env, "data-1k", ["-vvv", "--http1.1"])
        self.curl_upload_and_verify(env, "data-1k", ["--http2"])

    def test_h2_004_02(self, env):
        self.curl_upload_and_verify(env, "data-10k", ["--http1.1"])
        self.curl_upload_and_verify(env, "data-10k", ["--http2"])

    def test_h2_004_03(self, env):
        self.curl_upload_and_verify(env, "data-100k", ["--http1.1"])
        self.curl_upload_and_verify(env, "data-100k", ["--http2"])

    def test_h2_004_04(self, env):
        self.curl_upload_and_verify(env, "data-1m", ["--http1.1"])
        self.curl_upload_and_verify(env, "data-1m", ["--http2"])

    def test_h2_004_05(self, env):
        self.curl_upload_and_verify(env, "data-1k", ["-v", "--http1.1", "-H", "Expect: 100-continue"])
        self.curl_upload_and_verify(env, "data-1k", ["-v", "--http2", "-H", "Expect: 100-continue"])

    @pytest.mark.skipif(True, reason="python3 regresses in chunked inputs to cgi")
    def test_h2_004_06(self, env):
        self.curl_upload_and_verify(env, "data-1k", ["--http1.1", "-H", "Content-Length: "])
        self.curl_upload_and_verify(env, "data-1k", ["--http2", "-H", "Content-Length: "])

    @pytest.mark.parametrize("name, value", [
        ("HTTP2", "on"),
        ("H2PUSH", "off"),
        ("H2_PUSHED", ""),
        ("H2_PUSHED_ON", ""),
        ("H2_STREAM_ID", "1"),
        ("H2_STREAM_TAG", r'\d+-1'),
    ])
    def test_h2_004_07(self, env, name, value):
        url = env.mkurl("https", "cgi", "/env.py")
        r = env.curl_post_value(url, "name", name)
        assert r.exit_code == 0
        assert r.response["status"] == 200
        m = re.match("{0}=(.*)".format(name), r.response["body"].decode('utf-8'))
        assert m
        assert re.match(value, m.group(1)) 

    # POST some data using nghttp and see it echo'ed properly back
    def nghttp_post_and_verify(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/echo.py")
        fpath = os.path.join(env.gen_dir, fname)

        r = env.nghttp().upload(url, fpath, options=options)
        assert r.exit_code == 0
        assert r.response["status"] >= 200 and r.response["status"] < 300

        with open(self.local_src(fpath), mode='rb') as file:
            src = file.read()
        assert 'request-length' in r.response["header"]
        assert int(r.response["header"]['request-length']) == len(src)
        if len(r.response["body"]) != len(src):
            sys.stderr.writelines(difflib.unified_diff(
                src.decode().splitlines(True),
                r.response["body"].decode().splitlines(True),
                fromfile='source',
                tofile='response'
            ))
            assert len(r.response["body"]) == len(src)
        assert r.response["body"] == src, f"expected '{src}', got '{r.response['body']}'"

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m"
    ])
    def test_h2_004_21(self, env, name):
        self.nghttp_post_and_verify(env, name, [])

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m",
    ])
    def test_h2_004_22(self, env, name, repeat):
        self.nghttp_post_and_verify(env, name, ["--no-content-length"])

    # upload and GET again using nghttp, compare to original content
    def nghttp_upload_and_verify(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/upload.py")
        fpath = os.path.join(env.gen_dir, fname)

        r = env.nghttp().upload_file(url, fpath, options=options)
        assert r.exit_code == 0
        assert r.response["status"] >= 200 and r.response["status"] < 300
        assert r.response["header"]["location"]

        r2 = env.nghttp().get(r.response["header"]["location"])
        assert r2.exit_code == 0
        assert r2.response["status"] == 200
        with open(self.local_src(fpath), mode='rb') as file:
            src = file.read()
        assert src == r2.response["body"]

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m"
    ])
    def test_h2_004_23(self, env, name, repeat):
        self.nghttp_upload_and_verify(env, name, [])

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m"
    ])
    def test_h2_004_24(self, env, name, repeat):
        self.nghttp_upload_and_verify(env, name, ["--expect-continue"])

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m"
    ])
    def test_h2_004_25(self, env, name, repeat):
        self.nghttp_upload_and_verify(env, name, ["--no-content-length"])

    def test_h2_004_30(self, env):
        # issue: #203
        resource = "data-1k"
        full_length = 1000
        chunk = 200
        self.curl_upload_and_verify(env, resource, ["-v", "--http2"])
        logfile = os.path.join(env.server_logs_dir, "test_004_30")
        if os.path.isfile(logfile):
            os.remove(logfile)
        H2Conf(env).add("""
LogFormat "{ \\"request\\": \\"%r\\", \\"status\\": %>s, \\"bytes_resp_B\\": %B, \\"bytes_tx_O\\": %O, \\"bytes_rx_I\\": %I, \\"bytes_rx_tx_S\\": %S }" issue_203
CustomLog logs/test_004_30 issue_203
        """).add_vhost_cgi().install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/files/{0}".format(resource))
        r = env.curl_get(url, 5, options=["--http2"])
        assert r.response["status"] == 200
        r = env.curl_get(url, 5, options=["--http1.1", "-H", "Range: bytes=0-{0}".format(chunk-1)])
        assert 206 == r.response["status"]
        assert chunk == len(r.response["body"].decode('utf-8'))
        r = env.curl_get(url, 5, options=["--http2", "-H", "Range: bytes=0-{0}".format(chunk-1)])
        assert 206 == r.response["status"]
        assert chunk == len(r.response["body"].decode('utf-8'))
        # now check what response lengths have actually been reported
        lines = open(logfile).readlines()
        log_h2_full = json.loads(lines[-3])
        log_h1 = json.loads(lines[-2])
        log_h2 = json.loads(lines[-1])
        assert log_h2_full['bytes_rx_I'] > 0
        assert log_h2_full['bytes_resp_B'] == full_length
        assert log_h2_full['bytes_tx_O'] > full_length
        assert log_h1['bytes_rx_I'] > 0         # input bytes recieved
        assert log_h1['bytes_resp_B'] == chunk  # response bytes sent (payload)
        assert log_h1['bytes_tx_O'] > chunk     # output bytes sent
        assert log_h2['bytes_rx_I'] > 0
        assert log_h2['bytes_resp_B'] == chunk
        assert log_h2['bytes_tx_O'] > chunk
        
    def test_h2_004_40(self, env):
        # echo content using h2test_module "echo" handler
        def post_and_verify(fname, options=None):
            url = env.mkurl("https", "cgi", "/h2test/echo")
            fpath = os.path.join(env.gen_dir, fname)
            r = env.curl_upload(url, fpath, options=options)
            assert r.exit_code == 0
            assert r.response["status"] >= 200 and r.response["status"] < 300
            
            ct = r.response["header"]["content-type"]
            mail_hd = "Content-Type: " + ct + "\r\nMIME-Version: 1.0\r\n\r\n"
            mime_msg = mail_hd.encode() + r.response["body"]
            # this MIME API is from hell
            body = email.parser.BytesParser().parsebytes(mime_msg)
            assert body
            assert body.is_multipart()
            filepart = None
            for part in body.walk():
                if fname == part.get_filename():
                    filepart = part
            assert filepart
            with open(self.local_src(fpath), mode='rb') as file:
                src = file.read()
            assert src == filepart.get_payload(decode=True)
        
        post_and_verify("data-1k", [])
