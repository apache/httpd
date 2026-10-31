import socket

import pytest

from .env import H1Conf


def _query(env, path, body="q=foo&limit=10", ctype="application/x-www-form-urlencoded",
           headers=None, method="QUERY", vhost="cgi"):
    url = env.mkurl("https", vhost, path)
    options = ["-X", method, "--data-binary", body]
    # an empty value makes curl drop the header it would add by itself
    options.extend(["-H", f"Content-Type: {ctype}" if ctype else "Content-Type:"])
    for h in (headers or []):
        options.extend(["-H", h])
    return env.curl_raw([url], options=options)


class TestQuery:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H1Conf(env)
        conf.add_vhost_cgi()
        conf.start_vhost(domains=[f"test1.{env.http_tld}"],
                         port=env.https_port, doc_root="htdocs/test1")
        conf.add([
            "<Location /limit/>",
            "  <Limit QUERY>",
            "    Require all denied",
            "  </Limit>",
            "</Location>",
            "<Location /method/>",
            "  Require method GET QUERY",
            "</Location>",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    # QUERY with content reaches a CGI handler unchanged
    def test_h1_008_01(self, env):
        r = _query(env, "/query.py?x=1", body="select=surname&limit=10")
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        j = r.json
        assert j["method"] == "QUERY"
        assert j["content_type"] == "application/x-www-form-urlencoded"
        assert j["query_string"] == "x=1"
        assert j["body"] == "select=surname&limit=10"

    # QUERY without Content-Type MUST fail (RFC 10008, Section 2)
    def test_h1_008_02(self, env):
        r = _query(env, "/query.py", ctype=None)
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 400

    # same, on a raw HTTP/1.1 connection: the 400 closes the connection
    # like any other 400 to a malformed request
    def test_h1_008_03(self, env):
        req = (f"QUERY /query.py HTTP/1.1\r\n"
               f"Host: cgi.{env.http_tld}\r\n"
               f"Content-Length: 5\r\n"
               f"\r\n"
               f"hello")
        with socket.create_connection(('localhost', int(env.http_port))) as sock:
            sock.sendall(req.encode())
            resp = b""
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                resp += chunk
        text = resp.decode(errors='replace')
        assert text.startswith("HTTP/1.1 400 "), text
        assert "Connection: close" in text, text

    # conditional QUERY gets a 304 like GET (RFC 10008, Section 2.6)
    @pytest.mark.parametrize("cond", [
        'If-None-Match: "query-1"',
        'If-None-Match: W/"query-1"',
        'If-Modified-Since: Sun, 31 Aug 2025 08:44:00 GMT',
    ])
    def test_h1_008_04(self, env, cond):
        r = _query(env, "/query.py", headers=[cond])
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 304

    # non-matching validators give the full result
    @pytest.mark.parametrize("cond", [
        'If-None-Match: "query-2"',
        'If-Modified-Since: Sat, 30 Aug 2025 08:44:00 GMT',
    ])
    def test_h1_008_05(self, env, cond):
        r = _query(env, "/query.py", headers=[cond])
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        assert r.json["method"] == "QUERY"

    # CGI output only gets the GET-style 304 for GET and QUERY, not POST
    def test_h1_008_06(self, env):
        r = _query(env, "/query.py", method="POST",
                   headers=['If-None-Match: "query-1"'])
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        assert r.json["method"] == "POST"

    # a static resource does not implement QUERY
    def test_h1_008_07(self, env):
        r = _query(env, "/index.html", vhost="test1")
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 405
        allow = r.response["header"]["allow"]
        assert "GET" in allow and "QUERY" not in allow

    # <Limit QUERY> and Require method know the method
    def test_h1_008_08(self, env):
        r = _query(env, "/limit/index.html", vhost="test1")
        assert r.response["status"] == 403
        r = env.curl_get(env.mkurl("https", "test1", "/limit/"))
        assert r.response["status"] != 403
        r = _query(env, "/method/", vhost="test1", method="POST")
        assert r.response["status"] == 403
        r = _query(env, "/method/", vhost="test1")
        assert r.response["status"] != 403
        env.httpd_error_log.ignore_recent(lognos=["AH01630"])


class TestQueryUnsafe:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H1Conf(env)
        conf.add("HttpProtocolOptions Unsafe")
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0

    # "HttpProtocolOptions Unsafe" lets QUERY without Content-Type through
    def test_h1_008_10(self, env):
        r = _query(env, "/query.py", ctype=None)
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        assert r.json["method"] == "QUERY"
        assert r.json["content_type"] == ""
