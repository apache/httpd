import pytest

from .env import H3Conf, data_bytes


class TestPost:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize("size", [0, 1, 64 * 1024, 1024 * 1024,
                                      5 * 1024 * 1024])
    def test_h3_101_01_echo(self, env, size):
        body = data_bytes(size)
        r = env.h3_client(timeout=30).request("POST", "/cgi/raw-echo.py", body=body)
        assert r.status == 200, f"{r}"
        assert r.header("x-request-length") == str(size)
        assert r.body == body

    def test_h3_101_02_content_length(self, env):
        body = data_bytes(10000)
        r = env.h3_client().request("POST", "/cgi/raw-echo.py", body=body,
                                    headers=[("content-length", "10000")])
        assert r.status == 200, f"{r}"
        assert r.body == body

    def test_h3_101_03_expect_continue(self, env):
        body = data_bytes(1000)
        r = env.h3_client().request("POST", "/cgi/raw-echo.py", body=body,
                                    headers=[("expect", "100-continue")])
        assert r.status == 200, f"{r}"
        assert r.body == body

    def test_h3_101_04_concurrent(self, env):
        bodies = [data_bytes(50000 + i) for i in range(10)]
        rs = env.h3_client(timeout=30).requests([
            dict(method="POST", path="/cgi/raw-echo.py", body=b) for b in bodies])
        assert [r.status for r in rs] == [200] * 10, f"{rs}"
        assert [r.body for r in rs] == bodies


class TestPostLimit:

    LIMIT = 100000

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost(directives=[
            f"H3MaxRequestBodySize {cls.LIMIT}",
        ]).install()
        assert env.apache_restart() == 0

    def test_h3_101_10_at_limit(self, env):
        body = data_bytes(self.LIMIT)
        r = env.h3_client().request("POST", "/cgi/raw-echo.py", body=body)
        assert r.status == 200, f"{r}"
        assert r.body == body

    def test_h3_101_11_over_limit(self, env):
        r = env.h3_client().request("POST", "/cgi/raw-echo.py",
                                    body=data_bytes(self.LIMIT + 1))
        assert r.status == 413, f"{r}"
