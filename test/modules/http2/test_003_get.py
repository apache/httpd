import re
import pytest

from h2_conf import HttpdConf


class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        HttpdConf(env).add_vhost_cgi(
            proxy_self=True, h2proxy_self=True
        ).add_vhost_test1(
            proxy_self=True, h2proxy_self=True
        ).install()
        assert env.apache_restart() == 0

    # check SSL environment variables from CGI script
    def test_003_01(self, env):
        url = env.mkurl("https", "cgi", "/hello.py")
        r = env.curl_get(url, 5, ["--tlsv1.2"])
        assert 200 == r.response["status"]
        assert "HTTP/2.0" == r.response["json"]["protocol"]
        assert "on" == r.response["json"]["https"]
        tls_version = r.response["json"]["ssl_protocol"]
        assert tls_version in ["TLSv1.2", "TLSv1.3"]
        assert "on" == r.response["json"]["h2"]
        assert "off" == r.response["json"]["h2push"]

        r = env.curl_get(url, 5, ["--http1.1", "--tlsv1.2"])
        assert 200 == r.response["status"]
        assert "HTTP/1.1" == r.response["json"]["protocol"]
        assert "on" == r.response["json"]["https"]
        tls_version = r.response["json"]["ssl_protocol"]
        assert tls_version in ["TLSv1.2", "TLSv1.3"]
        assert "" == r.response["json"]["h2"]
        assert "" == r.response["json"]["h2push"]

    # retrieve a html file from the server and compare it to its source
    def test_003_02(self, env):
        with open(env.test_src("htdocs/test1/index.html"), mode='rb') as file:
            src = file.read()

        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_get(url, 5)
        assert 200 == r.response["status"]
        assert "HTTP/2" == r.response["protocol"]
        assert src == r.response["body"]

        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_get(url, 5, ["--http1.1"])
        assert 200 == r.response["status"]
        assert "HTTP/1.1" == r.response["protocol"]
        assert src == r.response["body"]

    # retrieve chunked content from a cgi script
    def check_necho(self, env, n, text):
        url = env.mkurl("https", "cgi", "/necho.py")
        r = env.curl_get(url, 5, ["-F", f"count={n}", "-F", f"text={text}"])
        assert 200 == r.response["status"]
        exp = ""
        for i in range(n):
            exp += text + "\n"
        assert exp == r.response["body"].decode('utf-8')
    
    def test_003_10(self, env):
        self.check_necho(env, 10, "0123456789")

    def test_003_11(self, env):
        self.check_necho(env, 100, "0123456789")

    def test_003_12(self, env):
        self.check_necho(env, 1000, "0123456789")

    def test_003_13(self, env):
        self.check_necho(env, 10000, "0123456789")

    def test_003_14(self, env):
        self.check_necho(env, 100000, "0123456789")

    # github issue #126
    def test_003_20(self, env):
        url = env.mkurl("https", "test1", "/006/")
        r = env.curl_get(url, 5)
        assert 200 == r.response["status"]
        body = r.response["body"].decode('utf-8')
        # our doctype varies between branches and in time, lets not compare
        body = re.sub(r'^<!DOCTYPE[^>]+>', '', body)
        assert '''
<html>
 <head>
  <title>Index of /006</title>
 </head>
 <body>
<title>My Header Title</title>
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
        
    def test_003_21(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_get(url, 5, ["-I"])
        assert 200 == r.response["status"]
        assert "HTTP/2" == r.response["protocol"]
        s = self.clean_header(r.response["body"].decode('utf-8'))
        assert '''HTTP/2 200 
content-length: 2007
content-type: text/html

''' == s

        r = env.curl_get(url, 5, ["-I", url])
        assert 200 == r.response["status"]
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
    def test_003_30(self, env, path):
        url = env.mkurl("https", "test1", path)
        r = env.curl_get(url, 5)
        assert 200 == r.response["status"]
        assert "HTTP/2" == r.response["protocol"]
        h = r.response["header"]
        assert "last-modified" in h
        lastmod = h["last-modified"]
        r = env.curl_get(url, 5, ['-H', ("if-modified-since: %s" % lastmod)])
        assert 304 == r.response["status"]

    # test conditionals: if-etag
    @pytest.mark.parametrize("path", [
        "/004.html", "/proxy/004.html", "/h2proxy/004.html"
    ])
    def test_003_31(self, env, path):
        url = env.mkurl("https", "test1", path)
        r = env.curl_get(url, 5)
        assert 200 == r.response["status"]
        assert "HTTP/2" == r.response["protocol"]
        h = r.response["header"]
        assert "etag" in h
        etag = h["etag"]
        r = env.curl_get(url, 5, ['-H', ("if-none-match: %s" % etag)])
        assert 304 == r.response["status"]

    # test various response body lengths to work correctly 
    def test_003_40(self, env):
        n = 1001
        while n <= 1025024:
            url = env.mkurl("https", "cgi", f"/mnot164.py?count={n}&text=X")
            r = env.curl_get(url, 5)
            assert 200 == r.response["status"]
            assert "HTTP/2" == r.response["protocol"]
            assert n == len(r.response["body"])
            n *= 2

    # test various response body lengths to work correctly 
    @pytest.mark.parametrize("n", [
        0, 1, 1291, 1292, 80000, 80123, 81087, 98452
    ])
    def test_003_41(self, env, n):
        url = env.mkurl("https", "cgi", f"/mnot164.py?count={n}&text=X")
        r = env.curl_get(url, 5)
        assert 200 == r.response["status"]
        assert "HTTP/2" == r.response["protocol"]
        assert n == len(r.response["body"])
        
    # test ranges
    @pytest.mark.parametrize("path", [
        "/004.html", "/proxy/004.html", "/h2proxy/004.html"
    ])
    def test_003_50(self, env, path):
        # check that the resource supports ranges and we see its raw content-length
        url = env.mkurl("https", "test1", path)
        r = env.curl_get(url, 5)
        assert 200 == r.response["status"]
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
