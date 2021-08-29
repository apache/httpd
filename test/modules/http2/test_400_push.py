import os
import pytest

from h2_conf import HttpdConf


# The push tests depend on "nghttp"
class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        HttpdConf(env).start_vhost(
            env.https_port, "push", doc_root="htdocs/test1", with_ssl=True
        ).add(r"""    Protocols h2 http/1.1"
        RewriteEngine on
        RewriteRule ^/006-push(.*)?\.html$ /006.html
        <Location /006-push.html>
            Header add Link "</006/006.css>;rel=preload"
            Header add Link "</006/006.js>;rel=preloadX"
        </Location>
        <Location /006-push2.html>
            Header add Link "</006/006.css>;rel=preloadX, </006/006.js>; rel=preload"
        </Location>
        <Location /006-push3.html>
            Header add Link "</006/006.css>;rel=preloa,</006/006.js>;rel=preload"
        </Location>
        <Location /006-push4.html>
            Header add Link "</006/006.css;rel=preload, </006/006.js>; preload"
        </Location>
        <Location /006-push5.html>
            Header add Link '</006/006.css>;rel="preload push"'
        </Location>
        <Location /006-push6.html>
            Header add Link '</006/006.css>;rel="push preload"'
        </Location>
        <Location /006-push7.html>
            Header add Link '</006/006.css>;rel="abc preload push"'
        </Location>
        <Location /006-push8.html>
            Header add Link '</006/006.css>;rel="preload"; nopush'
        </Location>
        <Location /006-push20.html>
            H2PushResource "/006/006.css" critical
            H2PushResource "/006/006.js"
        </Location>    
        <Location /006-push30.html>
            H2Push off
            Header add Link '</006/006.css>;rel="preload"'
        </Location>
        <Location /006-push31.html>
            H2PushResource "/006/006.css" critical
        </Location>
        <Location /006-push32.html>
            Header add Link "</006/006.css>;rel=preload"
        </Location>
        """).end_vhost(
        ).install()
        assert env.apache_restart() == 0

    ############################
    # Link: header handling, various combinations

    # plain resource without configured pushes 
    def test_400_00(self, env):
        url = env.mkurl("https", "push", "/006.html")
        r = env.nghttp().get(url)
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 0 == len(promises)

    # 2 link headers configured, only 1 triggers push
    def test_400_01(self, env):
        url = env.mkurl("https", "push", "/006-push.html")
        r = env.nghttp().get(url, options=["-Haccept-encoding: none"])
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 1 == len(promises)
        assert '/006/006.css' == promises[0]["request"]["header"][":path"]
        assert 216 == len(promises[0]["response"]["body"])

    # Same as 400_01, but with single header line configured
    def test_400_02(self, env):
        url = env.mkurl("https", "push", "/006-push2.html")
        r = env.nghttp().get(url)
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 1 == len(promises)
        assert '/006/006.js' == promises[0]["request"]["header"][":path"]

    # 2 Links, only one with correct rel attribue
    def test_400_03(self, env):
        url = env.mkurl("https", "push", "/006-push3.html")
        r = env.nghttp().get(url)
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 1 == len(promises)
        assert '/006/006.js' == promises[0]["request"]["header"][":path"]

    # Missing > in Link header, PUSH not triggered
    def test_400_04(self, env):
        url = env.mkurl("https", "push", "/006-push4.html")
        r = env.nghttp().get(url)
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 0 == len(promises)

    # More than one value in "rel" parameter
    def test_400_05(self, env):
        url = env.mkurl("https", "push", "/006-push5.html")
        r = env.nghttp().get(url)
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 1 == len(promises)
        assert '/006/006.css' == promises[0]["request"]["header"][":path"]

    # Another "rel" parameter variation
    def test_400_06(self, env):
        url = env.mkurl("https", "push", "/006-push6.html")
        r = env.nghttp().get(url)
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 1 == len(promises)
        assert '/006/006.css' == promises[0]["request"]["header"][":path"]

    # Another "rel" parameter variation
    def test_400_07(self, env):
        url = env.mkurl("https", "push", "/006-push7.html")
        r = env.nghttp().get(url)
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 1 == len(promises)
        assert '/006/006.css' == promises[0]["request"]["header"][":path"]

    # Pushable link header with "nopush" attribute
    def test_400_08(self, env):
        url = env.mkurl("https", "push", "/006-push8.html")
        r = env.nghttp().get(url)
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 0 == len(promises)

    # 2 H2PushResource config trigger on GET, but not on POST
    def test_400_20(self, env):
        url = env.mkurl("https", "push", "/006-push20.html")
        r = env.nghttp().get(url)
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 2 == len(promises)

        fpath = os.path.join(env.gen_dir, "data-400-20")
        with open(fpath, 'w') as f:
            f.write("test upload data")
        r = env.nghttp().upload(url, fpath)
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 0 == len(promises)
    
    # H2Push configured Off in location
    def test_400_30(self, env):
        url = env.mkurl("https", "push", "/006-push30.html")
        r = env.nghttp().get(url)
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 0 == len(promises)

    # - suppress PUSH
    def test_400_50(self, env):
        url = env.mkurl("https", "push", "/006-push.html")
        r = env.nghttp().get(url, options=['-H', 'accept-push-policy: none'])
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 0 == len(promises)

    # - default pushes desired
    def test_400_51(self, env):
        url = env.mkurl("https", "push", "/006-push.html")
        r = env.nghttp().get(url, options=['-H', 'accept-push-policy: default'])
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 1 == len(promises)

    # - HEAD pushes desired
    def test_400_52(self, env):
        url = env.mkurl("https", "push", "/006-push.html")
        r = env.nghttp().get(url, options=['-H', 'accept-push-policy: head'])
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 1 == len(promises)
        assert '/006/006.css' == promises[0]["request"]["header"][":path"]
        assert b"" == promises[0]["response"]["body"]
        assert 0 == len(promises[0]["response"]["body"])

    # - fast-load pushes desired
    def test_400_53(self, env):
        url = env.mkurl("https", "push", "/006-push.html")
        r = env.nghttp().get(url, options=['-H', 'accept-push-policy: fast-load'])
        assert 200 == r.response["status"]
        promises = r.results["streams"][r.response["id"]]["promises"]
        assert 1 == len(promises)
