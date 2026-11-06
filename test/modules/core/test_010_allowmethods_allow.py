import pytest

from pyhttpd.conf import HttpdConf

BASE = "/allowmethods"


def _conf(env, trace):
    conf = HttpdConf(env)
    conf.add(f"TraceEnable {trace}")
    conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.http_port,
                     doc_root="htdocs/allowmethods", with_ssl=False)
    conf.add([
        '<Location "/get-head-options/">',
        '    AllowMethods GET HEAD OPTIONS',
        '</Location>',
        '<Location "/get-post-options/">',
        '    AllowMethods GET POST OPTIONS',
        '</Location>',
        '<Location "/get/">',
        '    AllowMethods GET',
        '</Location>',
        '<Location "/get-post/">',
        '    AllowMethods GET POST',
        '</Location>',
        '<Location "/merge/">',
        '    AllowMethods GET POST OPTIONS',
        '</Location>',
        '<Location "/merge/child/">',
        '    AllowMethods -POST',
        '</Location>',
    ])
    conf.end_vhost()
    conf.install()
    assert env.apache_restart() == 0


def _request(env, method, path):
    options = ['-I'] if method == 'HEAD' else ['-X', method]
    r = env.curl_get(env.mkurl("http", "test1", f"{path}f.txt"),
                     options=options)
    assert r.response, f"no response: {r.stderr}"
    # denied on purpose
    env.httpd_error_log.ignore_recent(lognos=["AH01623", "AH00135"])
    allow = r.response["header"].get("allow")
    methods = None if allow is None else \
        {m.strip() for m in allow.split(',') if m.strip()}
    return r.response["status"], methods


class TestAllowMethodsAllow:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        _conf(env, "on")

    # a 405 lists the methods the resource does support
    @pytest.mark.parametrize("path, supported", [
        ("/get-head-options/", {"GET", "HEAD", "OPTIONS"}),
        ("/get-post-options/", {"GET", "HEAD", "POST", "OPTIONS"}),
        ("/get/", {"GET", "HEAD"}),
        ("/get-post/", {"GET", "HEAD", "POST"}),
        ("/merge/", {"GET", "HEAD", "POST", "OPTIONS"}),
        ("/merge/child/", {"GET", "HEAD", "OPTIONS"}),
    ])
    @pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
    def test_core_010_001(self, env, path, supported, method):
        status, allow = _request(env, method, path)
        assert status == 405
        # TRACE is not up to AllowMethods
        assert allow == supported | {"TRACE"}, f"{method} {path}: {allow}"

    def test_core_010_002(self, env):
        status, allow = _request(env, "POST", "/get-head-options/")
        assert status == 405
        assert allow == {"GET", "HEAD", "OPTIONS", "TRACE"}
        status, allow = _request(env, "POST", "/get/")
        assert status == 405
        assert allow == {"GET", "HEAD", "TRACE"}

    # the methods that are listed do work
    @pytest.mark.parametrize("method, path, status", [
        ("GET", "/get-head-options/", 200),
        ("HEAD", "/get-head-options/", 200),
        ("OPTIONS", "/get-head-options/", 200),
        ("GET", "/get/", 200),
        ("HEAD", "/get/", 200),
        ("POST", "/get-post/", 200),
        ("POST", "/merge/", 200),
        ("POST", "/merge/child/", 405),
        ("TRACE", "/get-head-options/", 200),
    ])
    def test_core_010_003(self, env, method, path, status):
        assert _request(env, method, path)[0] == status

    # a method the resource handler refuses is answered as before
    def test_core_010_004(self, env):
        status, allow = _request(env, "PUT", "/get-post-options/")
        assert status == 405
        assert allow == {"GET", "HEAD", "POST", "OPTIONS", "TRACE"}

    # without AllowMethods nothing changes
    def test_core_010_005(self, env):
        status, allow = _request(env, "PUT", "/plain/")
        assert status == 405
        assert allow == {"GET", "HEAD", "POST", "OPTIONS", "TRACE"}
        assert _request(env, "FROBNICATE", "/plain/")[0] == 501


class TestAllowMethodsAllowNoTrace:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        _conf(env, "off")

    # TraceEnable decides about TRACE
    def test_core_010_101(self, env):
        status, allow = _request(env, "PUT", "/get-head-options/")
        assert status == 405
        assert allow == {"GET", "HEAD", "OPTIONS"}
        assert _request(env, "TRACE", "/get-head-options/")[0] == 405
