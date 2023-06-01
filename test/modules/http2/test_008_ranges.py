import inspect
import json
import os
import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestRanges:

    LOGFILE = ""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        TestRanges.LOGFILE = os.path.join(env.server_logs_dir, "test_008")
        TestRanges.SRCDIR = os.path.dirname(inspect.getfile(TestRanges))
        if os.path.isfile(TestRanges.LOGFILE):
            os.remove(TestRanges.LOGFILE)
        destdir = os.path.join(env.gen_dir, 'apache/htdocs/test1')
        env.make_data_file(indir=destdir, fname="data-100m", fsize=100*1024*1024)
        conf = H2Conf(env=env)
        conf.add([
            "CustomLog logs/test_008 combined"
        ])
        conf.add_vhost_cgi()
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_h2_008_01(self, env):
        # issue: #203
        resource = "data-1k"
        full_length = 1000
        chunk = 200
        self.curl_upload_and_verify(env, resource, ["-v", "--http2"])
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", f"/files/{resource}?01full")
        r = env.curl_get(url, 5, options=["--http2"])
        assert r.response["status"] == 200
        url = env.mkurl("https", "cgi", f"/files/{resource}?01range")
        r = env.curl_get(url, 5, options=["--http1.1", "-H", "Range: bytes=0-{0}".format(chunk-1)])
        assert 206 == r.response["status"]
        assert chunk == len(r.response["body"].decode('utf-8'))
        r = env.curl_get(url, 5, options=["--http2", "-H", "Range: bytes=0-{0}".format(chunk-1)])
        assert 206 == r.response["status"]
        assert chunk == len(r.response["body"].decode('utf-8'))
        # Restart for logs to be flushed out
        assert env.apache_restart() == 0
        # now check what response lengths have actually been reported
        detected = {}
        for line in open(TestRanges.LOGFILE).readlines():
            e = json.loads(line)
            if e['request'] == f'GET /files/{resource}?01full HTTP/2.0':
                assert e['bytes_rx_I'] > 0
                assert e['bytes_resp_B'] == full_length
                assert e['bytes_tx_O'] > full_length
                detected['h2full'] = 1
            elif e['request'] == f'GET /files/{resource}?01range HTTP/2.0':
                assert e['bytes_rx_I'] > 0
                assert e['bytes_resp_B'] == chunk
                assert e['bytes_tx_O'] > chunk
                assert e['bytes_tx_O'] < chunk + 256 # response + frame stuff
                detected['h2range'] = 1
            elif e['request'] == f'GET /files/{resource}?01range HTTP/1.1':
                assert e['bytes_rx_I'] > 0         # input bytes received
                assert e['bytes_resp_B'] == chunk  # response bytes sent (payload)
                assert e['bytes_tx_O'] > chunk     # output bytes sent
                detected['h1range'] = 1
        assert 'h1range' in detected, f'HTTP/1.1 range request not found in {TestRanges.LOGFILE}'
        assert 'h2range' in detected, f'HTTP/2 range request not found in {TestRanges.LOGFILE}'
        assert 'h2full' in detected, f'HTTP/2 full request not found in {TestRanges.LOGFILE}'

    def test_h2_008_02(self, env, repeat):
        path = '/002.jpg'
        res_len = 90364
        url = env.mkurl("https", "test1", f'{path}?02full')
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert "HTTP/2" == r.response["protocol"]
        h = r.response["header"]
        assert "accept-ranges" in h
        assert "bytes" == h["accept-ranges"]
        assert "content-length" in h
        clen = h["content-length"]
        assert int(clen) == res_len
        # get the first 1024 bytes of the resource, 206 status, but content-length as original
        url = env.mkurl("https", "test1", f'{path}?02range')
        r = env.curl_get(url, 5, options=["-H", "range: bytes=0-1023"])
        assert 206 == r.response["status"]
        assert "HTTP/2" == r.response["protocol"]
        assert 1024 == len(r.response["body"])
        assert "content-length" in h
        assert clen == h["content-length"]
        # Restart for logs to be flushed out
        assert env.apache_restart() == 0
        # now check what response lengths have actually been reported
        found = False
        for line in open(TestRanges.LOGFILE).readlines():
            e = json.loads(line)
            if e['request'] == f'GET {path}?02range HTTP/2.0':
                assert e['bytes_rx_I'] > 0
                assert e['bytes_resp_B'] == 1024
                assert e['bytes_tx_O'] > 1024
                assert e['bytes_tx_O'] < 1024 + 256  # response  and frame stuff
                found = True
                break
        assert found, f'request not found in {self.LOGFILE}'

    # send a paced curl download that aborts in the middle of the transfer
    def test_h2_008_03(self, env, repeat):
        if not env.httpd_is_at_least('2.5.0'):
            pytest.skip(f'needs r1909769 from trunk')
        path = '/data-100m'
        url = env.mkurl("https", "test1", f'{path}?03broken')
        r = env.curl_get(url, 5, options=[
            '--limit-rate', '2k', '-m', '2'
        ])
        assert r.exit_code != 0, f'{r}'
        found = False
        for line in open(TestRanges.LOGFILE).readlines():
            e = json.loads(line)
            if e['request'] == f'GET {path}?03broken HTTP/2.0':
                assert e['bytes_rx_I'] > 0
                assert e['bytes_resp_B'] == 100*1024*1024
                assert e['bytes_tx_O'] > 1024
                assert e['bytes_tx_O'] < 10*1024*1024  # curl buffers, but not that much
                found = True
                break
        assert found, f'request not found in {self.LOGFILE}'

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
        with open(os.path.join(TestRanges.SRCDIR, fpath), mode='rb') as file:
            src = file.read()
        assert src == r2.response["body"]

