import os
import time

import pytest

from pyhttpd.conf import HttpdConf


class TestProxyHttp:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # setup 3 vhosts on https: for reverse, forward and mixed proxying
        # setup 3 vhosts on http: with different document roots
        conf = HttpdConf(env)
        conf.add("ProxyPreserveHost on")
        conf.start_vhost(domains=[env.d_reverse], port=env.https_port)
        conf.add([
            f"ProxyPass / http://127.0.0.1:{env.http_port}/"
        ])
        conf.end_vhost()
        conf.add_vhost(domains=[env.d_reverse], port=env.http_port, doc_root='htdocs/test1')

        conf.start_vhost(domains=[env.d_forward], port=env.https_port)
        conf.add([
            "ProxyRequests on"
        ])
        conf.end_vhost()
        conf.add_vhost(domains=[env.d_forward], port=env.http_port, doc_root='htdocs/test2')

        conf.start_vhost(domains=[env.d_mixed], port=env.https_port)
        conf.add([
            f"ProxyPass / http://127.0.0.1:{env.http_port}/",
            "ProxyRequests on"
        ])
        conf.end_vhost()
        conf.add_vhost(domains=[env.d_mixed], port=env.http_port, doc_root='htdocs')
        conf.install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize(["via", "seen"], [
        ["reverse", "test1"],
        ["mixed", "generic"],
    ])
    def test_proxy_01_001(self, env, via, seen):
        # make requests to a reverse proxy https: vhost to the http: vhost
        # check that we see the document we expect there (host matching worked)
        r = env.curl_get(f"https://{via}.{env.http_tld}:{env.https_port}/alive.json", 5)
        assert r.response["status"] == 200
        assert r.json['host'] == seen

    @pytest.mark.parametrize(["via", "seen"], [
        ["reverse", "test1"],
        ["forward", "test2"],
        ["mixed", "generic"],
    ])
    def test_proxy_01_002(self, env, via, seen):
        # make requests to a forward proxy https: vhost to the http: vhost
        # check that we see the document we expect there (host matching worked)
        # we need to explicitly provide a Host: header since mod_proxy cannot
        # resolve the name via DNS.
        env.require(env.curl_is_at_least('8.0.0'),
                    'need at least curl v8.0.0 for this',
                    dep='curl >= 8.0.0',
                    detected=f"curl {env.curl_version_str()}")
        domain = f"{via}.{env.http_tld}"
        r = env.curl_get(f"http://127.0.0.1:{env.http_port}/alive.json", 5, options=[
            '-H', f"Host: {domain}",
            '--proxy', f"https://{domain}:{env.https_port}/",
            '--resolve', f"{domain}:{env.https_port}:127.0.0.1",
            '--proxy-cacert', f"{env.get_ca_pem_file(domain)}",

        ])
        assert r.exit_code == 0, f"{r.stdout}{r.stderr}"
        assert r.response["status"] == 200
        assert r.json['host'] == seen

    def test_proxy_01_003(self, env):
        domain = f"test1.{env.http_tld}"
        conf = HttpdConf(env)
        conf.add([
            "ProxyPreserveHost on",
            "<Proxy balancer://backends>",
            f"  BalancerMember https://localhost:{env.https_port}",
            "  SSLProxyEngine on",
            "</Proxy>",
        ])
        conf.start_vhost(domains=[domain], port=env.https_port, doc_root="htdocs/test1")
        conf.add([
            "ProxyPass /proxy balancer://backends",
            "ProxyPassReverse /proxy balancer://backends",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        r = env.curl_get(f"https://{domain}:{env.https_port}/proxy/alive.json", 5)
        assert r.response["status"] == 200
        assert r.json['host'] == "test1"

    # stickysession routes taken from a cookie or the query string
    def test_proxy_01_004(self, env):
        domain = f"test1.{env.http_tld}"
        conf = HttpdConf(env)
        conf.add([
            "ProxyPreserveHost on",
            "<Proxy balancer://sticky>",
            f"  BalancerMember http://localhost:{env.http_port} route=r1",
            f"  BalancerMember http://127.0.0.1:{env.http_port} route=r2",
            "  ProxySet stickysession=ROUTEID|routeid",
            "</Proxy>",
        ])
        conf.start_vhost(domains=[domain], port=env.https_port, doc_root="htdocs/test1")
        conf.add([
            "ProxyPass /sticky balancer://sticky",
            'Header set X-Route "%{BALANCER_WORKER_ROUTE}e"',
        ])
        conf.end_vhost()
        conf.add_vhost(domains=[domain], port=env.http_port, doc_root="htdocs/test1")
        conf.install()
        assert env.apache_restart() == 0
        url = f"https://{domain}:{env.https_port}/sticky/alive.json"
        for route in ["r1", "r2"]:
            for _ in range(3):
                r = env.curl_get(url, options=["-H", f"Cookie: ROUTEID=s.{route}"])
                assert r.response["status"] == 200
                assert r.response["header"]["x-route"] == route
                r = env.curl_get(f"{url}?routeid=s.{route}")
                assert r.response["status"] == 200
                assert r.response["header"]["x-route"] == route
        # a session name without a value selects no route
        for cookie in ["ROUTEID", "a=b; ROUTEID", "ROUTEID ", "ROUTEID="]:
            r = env.curl_get(url, options=["-H", f"Cookie: {cookie}"])
            assert r.response["status"] == 200
            assert r.response["header"]["x-route"] in ["r1", "r2"]
        for query in ["routeid", "a=b&routeid", "routeid="]:
            r = env.curl_get(f"{url}?{query}")
            assert r.response["status"] == 200
            assert r.response["header"]["x-route"] in ["r1", "r2"]
        # a later cookie with a value is still found
        r = env.curl_get(url, options=["-H", "Cookie: ROUTEID; ROUTEID=s.r2"])
        assert r.response["status"] == 200
        assert r.response["header"]["x-route"] == "r2"
