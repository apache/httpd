import socket

import pytest

from .env import H1Conf


class TestGet:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H1Conf(env).add_vhost_cgi(
            proxy_self=True
        ).add_vhost_test1(
            proxy_self=True
        ).install()
        assert env.apache_restart() == 0

    # check SSL environment variables from CGI script
    def test_h1_003_01(self, env):
        url = env.mkurl("https", "cgi", "/hello.py")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        assert r.response["json"]["protocol"] == "HTTP/1.1"
        assert r.response["json"]["https"] == "on"
        tls_version = r.response["json"]["ssl_protocol"]
        assert tls_version in ["TLSv1.2", "TLSv1.3"]
