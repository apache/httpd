import json
import os

import pytest

from .env import H3Conf, known_bug


class TestHeaders:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost(directives=[
            "<Location /many>",
            *[f"  Header always add X-Many {i}" for i in range(80)],
            "</Location>",
            "<Location /big>",
            f"  Header always set X-Big {'x' * 8000}",
            "</Location>",
            "LimitRequestFields 20",
            "LimitRequestFieldSize 1000",
        ]).install()
        assert env.apache_restart() == 0

    def test_h3_104_01_many_response_headers(self, env):
        url = f"https://{env.h3_domain}:{env.https_port}/many/"
        r = env.curl_get(url, options=["--http1.1", "-o", os.devnull,
                                         "-w", "%{header_json}"])
        assert len(json.loads(r.stdout)["x-many"]) == 80
        r = env.h3_client().get("/many/")
        n = len(r.header_values("x-many"))
        known_bug(n < 80, f"only {n} of 80 response headers arrive")

    def test_h3_104_02_big_response_header(self, env):
        r = env.h3_client().get("/big/")
        assert r.header("x-big") == "x" * 8000, f"{r}"

    def test_h3_104_03_too_many_fields(self, env):
        r = env.h3_client().get("/", headers=[(f"x-f{i}", "1") for i in range(25)])
        assert r.status == 431, f"{r}"

    def test_h3_104_04_field_too_large(self, env):
        r = env.h3_client().get("/", headers=[("x-long", "y" * 2000)])
        assert r.status == 431, f"{r}"

    def test_h3_104_05_fields_within_limits(self, env):
        r = env.h3_client().get("/", headers=[(f"x-f{i}", "z" * 900)
                                              for i in range(15)])
        assert r.status == 200, f"{r}"


class TestRequestLine:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost(directives=["LimitRequestLine 1000"]).install()
        assert env.apache_restart() == 0

    def test_h3_104_10_request_line(self, env):
        path = "/" + "p" * 2000
        url = f"https://{env.h3_domain}:{env.https_port}{path}"
        assert env.curl_get(url, options=["--http1.1"]).response["status"] == 414
        r = env.h3_client().get(path)
        env.httpd_error_log.ignore_recent(lognos=["AH00127"])
        known_bug(r.status == 403, "LimitRequestLine does not apply")
        assert r.status == 414 or r.reset is not None, f"{r}"
