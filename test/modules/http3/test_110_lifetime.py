import pytest

from .env import H3Conf, data_bytes

# Freed memory goes back to malloc (MaxMemFree) and is scribbled over, so
# anything mod_http3 reads from a request pool after it is gone shows up.
SCRIBBLE_ENV = {"MallocScribble": "1", "MALLOC_PERTURB_": "85"}


def _set_scribble(env, on: bool):
    for name, value in SCRIBBLE_ENV.items():
        env.set_httpd_env(name, value if on else None)


class TestLifetimeBuffered:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        _set_scribble(env, True)
        conf = H3Conf(env)
        conf.add("MaxMemFree 1")
        conf.add_h3_vhost(directives=[
            "H3MaxResponseBodySize 1000000",
            "Header always set X-Lifetime yes",
        ]).install()
        assert env.apache_restart() == 0
        yield
        _set_scribble(env, False)

    @pytest.mark.parametrize("path, size", [
        ("/h3data-1k", 1024), ("/h3data-100k", 100 * 1024),
    ])
    def test_h3_110_01_buffered_body(self, env, path, size):
        reqs = [dict(path=path)] * 5
        for r in env.h3_client().requests(reqs, sequential=True):
            assert r.status == 200, f"{r}"
            assert r.header("x-lifetime") == "yes", f"{r}"
            assert r.body == data_bytes(size)

    def test_h3_110_02_not_found(self, env):
        reqs = [dict(path="/nothing-here")] * 5
        for r in env.h3_client().requests(reqs, sequential=True):
            assert r.status == 404, f"{r}"
            assert r.header("x-lifetime") == "yes", f"{r}"


class TestLifetimeStreaming:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        _set_scribble(env, True)
        conf = H3Conf(env)
        conf.add("MaxMemFree 1")
        conf.add_h3_vhost(directives=[
            "Header always set X-Lifetime yes",
        ]).install()
        assert env.apache_restart() == 0
        yield
        _set_scribble(env, False)

    @pytest.mark.parametrize("method, path", [
        ("GET", "/h3data-1k"), ("HEAD", "/h3data-1k"), ("GET", "/nothing-here"),
    ])
    def test_h3_110_10_streamed(self, env, method, path):
        reqs = [dict(method=method, path=path)] * 5
        for r in env.h3_client().requests(reqs, sequential=True):
            assert r.status in (200, 404), f"{r}"
            assert r.header("x-lifetime") == "yes", f"{r}"
