import re
import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestGet:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add_vhost_cgi(
            proxy_self=True, h2proxy_self=True
        ).add_vhost_test1(
            proxy_self=True, h2proxy_self=True
        ).install()
        assert env.apache_restart() == 0

    # check SSL environment variables from CGI script
    def test_h2_003_01(self, env):
        url = env.mkurl("https", "cgi", "/hello.py")
        r = env.curl_get(url, 5, options=["--tlsv1.2"])
        assert r.response["status"] == 200
        assert r.response["json"]["protocol"] == "HTTP/2.0"
        assert r.response["json"]["https"] == "on"
        tls_version = r.response["json"]["ssl_protocol"]
        assert tls_version in ["TLSv1.2", "TLSv1.3"]
        assert r.response["json"]["h2"] == "on"
        assert r.response["json"]["h2push"] == "off"

        r = env.curl_get(url, 5, options=["--http1.1", "--tlsv1.2"])
        assert r.response["status"] == 200
        assert "HTTP/1.1" == r.response["json"]["protocol"]
        assert "on" == r.response["json"]["https"]
        tls_version = r.response["json"]["ssl_protocol"]
        assert tls_version in ["TLSv1.2", "TLSv1.3"]
        assert "" == r.response["json"]["h2"]
        assert "" == r.response["json"]["h2push"]

    # retrieve a html file from the server and compare it to its source
    def test_h2_003_02(self, env):
        with open(env.htdocs_src("test1/index.html"), mode='rb') as file:
            src = file.read()

        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert "HTTP/2" == r.response["protocol"]
        assert src == r.response["body"]

        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_get(url, 5, options=["--http1.1"])
        assert r.response["status"] == 200
        assert "HTTP/1.1" == r.response["protocol"]
        assert src == r.response["body"]

    # retrieve chunked content from a cgi script
    def check_necho(self, env, n, text):
        url = env.mkurl("https", "cgi", "/necho.py")
        r = env.curl_get(url, 5, options=["-F", f"count={n}", "-F", f"text={text}"])
        assert r.response["status"] == 200
        exp = ""
        for i in range(n):
            exp += text + "\n"
        assert exp == r.response["body"].decode('utf-8')
    
    def test_h2_003_10(self, env):
        self.check_necho(env, 10, "0123456789")

    def test_h2_003_11(self, env):
        self.check_necho(env, 100, "0123456789")

    def test_h2_003_12(self, env):
        self.check_necho(env, 1000, "0123456789")

    def test_h2_003_13(self, env):
        self.check_necho(env, 10000, "0123456789")

    def test_h2_003_14(self, env):
        self.check_necho(env, 100000, "0123456789")

    # github issue #126
    def test_h2_003_20(self, env):
        url = env.mkurl("https", "test1", "/006/")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        body = r.response["body"].decode('utf-8')
        # our doctype varies between branches and in time, lets not compare
        body = re.sub(r'^<!DOCTYPE[^>]+>', '', body)
        assert '''
<html>
 <head>
  <title>Index of /006</title>
 </head>
 <body>
<h1>Index of /006</h1>
<ul><li><a href="/"> Parent Directory</a></li>
<li><a href="006.css"> 006.css</a></li>
<li><a href="006.js"> 006.js</a></li>
<li><a href="header.html"> header.html</a></li>
</ul>
</body></html>
''' == body

    # github issue #133
    def clean_header(self, s):
        s = re.sub(r'\r\n', '\n', s, flags=re.MULTILINE)
        s = re.sub(r'^date:.*\n', '', s, flags=re.MULTILINE)
        s = re.sub(r'^server:.*\n', '', s, flags=re.MULTILINE)
        s = re.sub(r'^last-modified:.*\n', '', s, flags=re.MULTILINE)
        s = re.sub(r'^etag:.*\n', '', s, flags=re.MULTILINE)
        s = re.sub(r'^vary:.*\n', '', s, flags=re.MULTILINE)
        return re.sub(r'^accept-ranges:.*\n', '', s, flags=re.MULTILINE)
        
    def test_h2_003_21(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_get(url, 5, options=["-I"])
        assert r.response["status"] == 200
        assert "HTTP/2" == r.response["protocol"]
        s = self.clean_header(r.response["body"].decode('utf-8'))
        assert '''HTTP/2 200 
content-length: 2007
content-type: text/html

''' == s

        r = env.curl_get(url, 5, options=["-I", url])
        assert r.response["status"] == 200
        assert "HTTP/2" == r.response["protocol"]
        s = self.clean_header(r.response["body"].decode('utf-8'))
        assert '''HTTP/2 200 
content-length: 2007
content-type: text/html

HTTP/2 200 
content-length: 2007
content-type: text/html

''' == s

    # test conditionals: if-modified-since
    @pytest.mark.parametrize("path", [
        "/004.html", "/proxy/004.html", "/h2proxy/004.html"
    ])
    def test_h2_003_30(self, env, path):
        url = env.mkurl("https", "test1", path)
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert "HTTP/2" == r.response["protocol"]
        h = r.response["header"]
        assert "last-modified" in h
        lastmod = h["last-modified"]
        r = env.curl_get(url, 5, options=['-H', ("if-modified-since: %s" % lastmod)])
        assert 304 == r.response["status"]

    # test conditionals: if-etag
    @pytest.mark.parametrize("path", [
        "/004.html", "/proxy/004.html", "/h2proxy/004.html"
    ])
    def test_h2_003_31(self, env, path):
        url = env.mkurl("https", "test1", path)
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert "HTTP/2" == r.response["protocol"]
        h = r.response["header"]
        assert "etag" in h
        etag = h["etag"]
        r = env.curl_get(url, 5, options=['-H', ("if-none-match: %s" % etag)])
        assert 304 == r.response["status"]

    # test various response body lengths to work correctly 
    def test_h2_003_40(self, env):
        n = 1001
        while n <= 1025024:
            url = env.mkurl("https", "cgi", f"/mnot164.py?count={n}&text=X")
            r = env.curl_get(url, 5)
            assert r.response["status"] == 200
            assert "HTTP/2" == r.response["protocol"]
            assert n == len(r.response["body"])
            n *= 2

    # test various response body lengths to work correctly 
    @pytest.mark.parametrize("n", [
        0, 1, 1291, 1292, 80000, 80123, 81087, 98452
    ])
    def test_h2_003_41(self, env, n):
        url = env.mkurl("https", "cgi", f"/mnot164.py?count={n}&text=X")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert "HTTP/2" == r.response["protocol"]
        assert n == len(r.response["body"])
        
    # test ranges
    @pytest.mark.parametrize("path", [
        "/004.html", "/proxy/004.html", "/h2proxy/004.html"
    ])
    def test_h2_003_50(self, env, path):
        # check that the resource supports ranges and we see its raw content-length
        url = env.mkurl("https", "test1", path)
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert "HTTP/2" == r.response["protocol"]
        h = r.response["header"]
        assert "accept-ranges" in h
        assert "bytes" == h["accept-ranges"]
        assert "content-length" in h
        clen = h["content-length"]
        # get the first 1024 bytes of the resource, 206 status, but content-length as original
        r = env.curl_get(url, 5, options=["-H", "range: bytes=0-1023"])
        assert 206 == r.response["status"]
        assert "HTTP/2" == r.response["protocol"]
        assert 1024 == len(r.response["body"])
        assert "content-length" in h
        assert clen == h["content-length"]

    # use an invalid scheme
    def test_h2_003_51(self, env):
        url = env.mkurl("https", "cgi", "/")
        opt = ["-H:scheme: invalid"]
        r = env.nghttp().get(url, options=opt)
        assert r.exit_code == 0, r
        assert r.response['status'] == 400

    # use an differing scheme, but one that is acceptable
    def test_h2_003_52(self, env):
        url = env.mkurl("https", "cgi", "/")
        opt = ["-H:scheme: http"]
        r = env.nghttp().get(url, options=opt)
        assert r.exit_code == 0, r
        assert r.response['status'] == 200

    # Test that we get a proper `Date` and `Server` headers on responses
    def test_h2_003_60(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_get(url)
        assert r.exit_code == 0, r
        assert r.response['status'] == 200
        assert 'date' in r.response['header']
        assert 'server' in r.response['header']

    # lets do some error tests
    def test_h2_003_70(self, env):
        url = env.mkurl("https", "cgi", "/h2test/error?status=500")
        r = env.curl_get(url)
        assert r.exit_code == 0, r
        assert r.response['status'] == 500
        url = env.mkurl("https", "cgi", "/h2test/error?error=timeout")
        r = env.curl_get(url)
        assert r.exit_code == 0, r
        assert r.response['status'] == 408

    # produce an error during response body
    def test_h2_003_71(self, env, repeat):
        url = env.mkurl("https", "cgi", "/h2test/error?body_error=timeout")
        r = env.curl_get(url)
        assert r.exit_code != 0, f"{r}"
        url = env.mkurl("https", "cgi", "/h2test/error?body_error=reset")
        r = env.curl_get(url)
        assert r.exit_code != 0, f"{r}"

    # produce an error, fail to generate an error bucket
    def test_h2_003_72(self, env, repeat):
        url = env.mkurl("https", "cgi", "/h2test/error?body_error=timeout&error_bucket=0")
        r = env.curl_get(url)
        assert r.exit_code != 0, f"{r}"
