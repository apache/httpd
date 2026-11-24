import os

import pytest

from .env import H3Conf, data_bytes


class TestMisc:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        docs = os.path.join(env.server_docs_dir, "test1")
        with open(os.path.join(docs, "h3-404.html"), "w") as fd:
            fd.write("custom not found\n")
        with open(os.path.join(docs, "h3-ssi.shtml"), "w") as fd:
            fd.write('proto=<!--#echo var="SERVER_PROTOCOL" -->\n')
        H3Conf(env).add_h3_vhost(directives=[
            "ErrorDocument 404 /h3-404.html",
            "Header always set X-Always 1",
            "Redirect /h3-old /h3-new",
            "<Files *.shtml>",
            "  Options +Includes",
            "  SetOutputFilter INCLUDES",
            "</Files>",
            f"ProxyPass /proxy/ http://127.0.0.1:{env.http_port}/",
            "<Location /h3-location>",
            "</Location>",
        ]).install()
        assert env.apache_restart() == 0

    def test_h3_108_01_error_document(self, env):
        r = env.h3_client().get("/nothing-here")
        assert r.status == 404, f"{r}"
        assert r.body == b"custom not found\n"

    def test_h3_108_02_always_header_on_error(self, env):
        r = env.h3_client().get("/nothing-here")
        assert r.status == 404, f"{r}"
        assert r.header("x-always") == "1"

    def test_h3_108_03_redirect(self, env):
        r = env.h3_client().get("/h3-old")
        assert r.status == 302, f"{r}"
        assert r.header("location") == \
            f"https://{env.h3_domain}:{env.https_port}/h3-new"

    def test_h3_108_04_ssi(self, env):
        r = env.h3_client().get("/h3-ssi.shtml")
        assert r.status == 200, f"{r}"
        assert r.body == b"proto=HTTP/3.0\n"

    def test_h3_108_05_proxy_get(self, env):
        r = env.h3_client().get("/proxy/alive.json")
        assert r.status == 200, f"{r}"
        assert r.json["alive"] is True

    def test_h3_108_06_proxy_post(self, env):
        body = data_bytes(200000)
        r = env.h3_client(timeout=30).request("POST", "/proxy/cgi/raw-echo.py",
                                              body=body)
        assert r.status == 200, f"{r}"
        assert r.body == body

    def test_h3_108_07_connect_no_path(self, env):
        # A CONNECT has no :path. The location walk must not get a NULL URI.
        r1, r2 = env.h3_client().requests([dict(method="CONNECT"), dict(path="/")],
                                          sequential=True)
        assert 400 <= r1.status < 500, f"{r1}"
        assert r2.status == 200, f"{r2}"
