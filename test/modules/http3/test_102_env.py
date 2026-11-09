import pytest

from .env import H3Conf, known_bug


def cgi_env(client, **kwargs):
    r = client.get("/cgi/env.py", **kwargs)
    assert r.status == 200, f"{r}"
    return r.json


class TestEnv:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0

    def test_h3_102_01_request(self, env):
        e = cgi_env(env.h3_client())
        assert e["SERVER_PROTOCOL"] == "HTTP/3.0"
        assert e["REQUEST_METHOD"] == "GET"
        assert e["REQUEST_SCHEME"] == "https"
        assert e["HTTP_HOST"] == f"{env.h3_domain}:{env.https_port}"
        assert e["SERVER_NAME"] == env.h3_domain
        assert e["SERVER_PORT"] == str(env.https_port)
        assert e["REMOTE_ADDR"] == "127.0.0.1"

    def test_h3_102_02_query(self, env):
        r = env.h3_client().get("/cgi/env.py?a=1&b=%20")
        assert r.status == 200, f"{r}"
        assert r.json["QUERY_STRING"] == "a=1&b=%20"

    def test_h3_102_03_tls(self, env):
        e = cgi_env(env.h3_client())
        assert e["HTTPS"] == "on"
        assert e["SSL_PROTOCOL"] == "TLSv1.3"
        assert e["SSL_CIPHER"].startswith("TLS_")
        assert e["SSL_SESSION_RESUMED"] == "Initial"

    def test_h3_102_04_resumed(self, env):
        first = env.h3_client()
        assert cgi_env(first)["SSL_SESSION_RESUMED"] == "Initial"
        assert first.received_tickets, "no session ticket issued"
        again = env.h3_client(session_ticket=first.received_tickets[-1])
        assert cgi_env(again)["SSL_SESSION_RESUMED"] == "Resumed"

    def test_h3_102_05_scheme_header(self, env):
        e = cgi_env(env.h3_client())
        known_bug("HTTP_SCHEME" in e, "a 'Scheme' request header is made up "
                  "from :scheme")

    def test_h3_102_06_cookie_crumbs(self, env):
        # RFC 9114 4.2.1: split cookie fields are joined with "; "
        e = cgi_env(env.h3_client(), headers=[("cookie", "a=1"),
                                              ("cookie", "b=2")])
        known_bug(e.get("HTTP_COOKIE") != "a=1; b=2",
                  f"cookie crumbs joined as {e.get('HTTP_COOKIE')!r}")

    def test_h3_102_07_repeated_header(self, env):
        e = cgi_env(env.h3_client(), headers=[("x-multi", "1"),
                                              ("x-multi", "2")])
        known_bug(e["HTTP_X_MULTI"] == "2", "a repeated request header "
                  "keeps only its last value")
        assert e["HTTP_X_MULTI"] == "1, 2"


class TestNoTickets:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost(directives=["H3SessionTickets off"]).install()
        assert env.apache_restart() == 0

    def test_h3_102_10_no_tickets(self, env):
        client = env.h3_client()
        assert cgi_env(client)["SSL_SESSION_RESUMED"] == "Initial"
        assert client.received_tickets == []
