import pytest

from .env import H3Conf


class TestAccess:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H3Conf(env).add_h3_vhosts(test1=[
            'SetEnvIf User-Agent "^blocked-agent$" blocked',
            '<Location "/">',
            '  <RequireAll>',
            '    Require all granted',
            '    Require not env blocked',
            '  </RequireAll>',
            '</Location>',
            'SetEnvIf Request_Protocol "^(.+)$" seen_proto=$1',
            'Header always set X-Seen-Protocol "%{seen_proto}e"',
            # HTTP/3 field names are lowercase on the wire, as in HTTP/2
            'Header echo "(?i)^x-h3-echo$"',
        ]).install()
        assert env.apache_restart() == 0

    # SetEnvIf runs in post_read_request, so Require sees its variable
    def test_h3_003_01(self, env):
        client = env.h3_client()
        r = client.get("/alive.json", headers=[("user-agent", "blocked-agent")])
        assert r.status == 403, f"{r}"
        r = client.get("/alive.json", headers=[("user-agent", "other-agent")])
        assert r.status == 200, f"{r}"
        env.httpd_error_log.ignore_recent(lognos=["AH01630"])

    # SetEnvIf sees the request protocol that mod_http3 sets, and
    # mod_headers can use its variables and echo request headers
    def test_h3_003_02(self, env):
        r = env.h3_client().get("/alive.json", headers=[("x-h3-echo", "hello")])
        assert r.status == 200, f"{r}"
        assert r.header("x-seen-protocol") == "HTTP/3.0"
        assert r.header("x-h3-echo") == "hello"


class TestRequestChecks:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H3Conf(env)
        conf.add("StrictHostCheck on")
        conf.add_h3_vhosts().install()
        assert env.apache_restart() == 0

    # StrictHostCheck rejects a Host that matches no virtual host
    def test_h3_003_03(self, env):
        client = env.h3_client()
        r = client.get("/alive.json",
                       authority=f"unknown.{env.http_tld}:{env.https_port}")
        assert r.status == 400, f"{r}"
        env.httpd_error_log.ignore_recent(lognos=["AH10156", "AH10157"])
        r = client.get("/alive.json")
        assert r.status == 200, f"{r}"

    # an Expect other than 100-continue gives 417
    def test_h3_003_04(self, env):
        r = env.h3_client().get("/alive.json",
                                headers=[("expect", "something-else")])
        assert r.status == 417, f"{r}"
