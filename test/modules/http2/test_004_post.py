import email.parser
import json
import os
import re
import pytest

from h2_conf import HttpdConf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        env.setup_data_1k_1m()
        HttpdConf(env).add_vhost_cgi().install()
        assert env.apache_restart() == 0

    # upload and GET again using curl, compare to original content
    def curl_upload_and_verify(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/upload.py")
        fpath = os.path.join(env.gen_dir, fname)
        r = env.curl_upload(url, fpath, options=options)
        assert r.exit_code == 0, r.stderr
        assert r.response["status"] >= 200 and r.response["status"] < 300

        r2 = env.curl_get(r.response["header"]["location"])
        assert r2.exit_code == 0
        assert r2.response["status"] == 200
        with open(env.test_src(fpath), mode='rb') as file:
            src = file.read()
        assert src == r2.response["body"]

    def test_004_01(self, env):
        self.curl_upload_and_verify(env, "data-1k", ["--http1.1"])
        self.curl_upload_and_verify(env, "data-1k", ["--http2"])

    def test_004_02(self, env):
        self.curl_upload_and_verify(env, "data-10k", ["--http1.1"])
        self.curl_upload_and_verify(env, "data-10k", ["--http2"])

    def test_004_03(self, env):
        self.curl_upload_and_verify(env, "data-100k", ["--http1.1"])
        self.curl_upload_and_verify(env, "data-100k", ["--http2"])

    def test_004_04(self, env):
        self.curl_upload_and_verify(env, "data-1m", ["--http1.1"])
        self.curl_upload_and_verify(env, "data-1m", ["--http2"])

    def test_004_05(self, env):
        self.curl_upload_and_verify(env, "data-1k", ["-v", "--http1.1", "-H", "Expect: 100-continue"])
        self.curl_upload_and_verify(env, "data-1k", ["-v", "--http2", "-H", "Expect: 100-continue"])

    @pytest.mark.skipif(True, reason="python3 regresses in chunked inputs to cgi")
    def test_004_06(self, env):
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
    def test_004_07(self, env, name, value):
        url = env.mkurl("https", "cgi", "/env.py")
        r = env.curl_post_value(url, "name", name)
        assert r.exit_code == 0
        assert r.response["status"] == 200
        m = re.match("{0}=(.*)".format(name), r.response["body"].decode('utf-8'))
        assert m
        assert re.match(value, m.group(1)) 

    # verify that we parse nghttp output correctly
    def check_nghttp_body(self, env, ref_input, nghttp_output):
        with open(env.test_src(os.path.join(env.gen_dir, ref_input)), mode='rb') as f:
            refbody = f.read()
        with open(env.test_src(nghttp_output), mode='rb') as f:
            text = f.read()
        o = env.nghttp().parse_output(text)
        assert "response" in o
        assert "body" in o["response"]
        if refbody != o["response"]["body"]:
            with open(env.test_src(os.path.join(env.gen_dir, '%s.parsed' % ref_input)), mode='bw') as f:
                f.write(o["response"]["body"])
        assert len(refbody) == len(o["response"]["body"])
        assert refbody == o["response"]["body"]
    
    def test_004_20(self, env):
        self.check_nghttp_body(env, 'data-1k', 'data/nghttp-output-1k-1.txt')
        self.check_nghttp_body(env, 'data-10k', 'data/nghttp-output-10k-1.txt')
        self.check_nghttp_body(env, 'data-100k', 'data/nghttp-output-100k-1.txt')

    # POST some data using nghttp and see it echo'ed properly back
    def nghttp_post_and_verify(self, env, fname, options=None):
        url = env.mkurl("https", "cgi", "/echo.py")
        fpath = os.path.join(env.gen_dir, fname)

        r = env.nghttp().upload(url, fpath, options=options)
        assert r.exit_code == 0
        assert r.response["status"] >= 200 and r.response["status"] < 300

        with open(env.test_src(fpath), mode='rb') as file:
            src = file.read()
        assert src == r.response["body"]

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m"
    ])
    def test_004_21(self, env, name):
        self.nghttp_post_and_verify(env, name, [])

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m"
    ])
    def test_004_22(self, env, name, repeat):
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
        with open(env.test_src(fpath), mode='rb') as file:
            src = file.read()
        assert src == r2.response["body"]

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m"
    ])
    def test_004_23(self, env, name, repeat):
        self.nghttp_upload_and_verify(env, name, [])

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m"
    ])
    def test_004_24(self, env, name, repeat):
        self.nghttp_upload_and_verify(env, name, ["--expect-continue"])

    @pytest.mark.parametrize("name", [
        "data-1k", "data-10k", "data-100k", "data-1m"
    ])
    def test_004_25(self, env, name, repeat):
        self.nghttp_upload_and_verify(env, name, ["--no-content-length"])

    def test_004_30(self, env):
        # issue: #203
        resource = "data-1k"
        full_length = 1000
        chunk = 200
        self.curl_upload_and_verify(env, resource, ["-v", "--http2"])
        logfile = os.path.join(env.server_logs_dir, "test_004_30")
        if os.path.isfile(logfile):
            os.remove(logfile)
        HttpdConf(env).add("""
LogFormat "{ \\"request\\": \\"%r\\", \\"status\\": %>s, \\"bytes_resp_B\\": %B, \\"bytes_tx_O\\": %O, \\"bytes_rx_I\\": %I, \\"bytes_rx_tx_S\\": %S }" issue_203
CustomLog logs/test_004_30 issue_203
        """).add_vhost_cgi().install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/files/{0}".format(resource))
        r = env.curl_get(url, 5, ["--http2"])
        assert 200 == r.response["status"]
        r = env.curl_get(url, 5, ["--http1.1", "-H", "Range: bytes=0-{0}".format(chunk-1)])
        assert 206 == r.response["status"]
        assert chunk == len(r.response["body"].decode('utf-8'))
        r = env.curl_get(url, 5, ["--http2", "-H", "Range: bytes=0-{0}".format(chunk-1)])
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
        
    def test_004_40(self, env):
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
            with open(env.test_src(fpath), mode='rb') as file:
                src = file.read()
            assert src == filepart.get_payload(decode=True)
        
        post_and_verify("data-1k", [])
