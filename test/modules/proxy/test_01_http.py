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
        if not env.curl_is_at_least('8.0.0'):
            pytest.skip(f'need at least curl v8.0.0 for this')
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
