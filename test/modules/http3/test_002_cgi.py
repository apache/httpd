import pytest

from .env import H3Conf


class TestCgi:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhosts().install()
        assert env.apache_restart() == 0

    # a CGI script sees the request as HTTP/3 over TLS
    def test_h3_002_01(self, env):
        r = env.h3_get(env.mkurl("https", "cgi", "/echo.py?a=b"))
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        assert r.json["request_method"] == "GET"
        assert r.json["server_protocol"] == "HTTP/3.0"
        assert r.json["https"] == "on"
        assert r.json["query_string"] == "a=b"
        assert r.json["body_len"] == 0

    # POST content reaches the script complete
    @pytest.mark.parametrize("size", [1, 1024, 100 * 1024, 1024 * 1024])
    def test_h3_002_02(self, env, size):
        data = (b"0123456789abcdef" * (size // 16 + 1))[:size - 1] + b"!"
        fpath = f"{env.gen_dir}/h3-post-{size}"
        with open(fpath, "wb") as fd:
            fd.write(data)
        r = env.h3_get(env.mkurl("https", "cgi", "/echo.py"), options=[
            "--data-binary", f"@{fpath}",
            "-H", "Content-Type: application/octet-stream",
        ])
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        assert r.json["request_method"] == "POST"
        assert r.json["content_type"] == "application/octet-stream"
        assert r.json["body_len"] == size
        assert r.json["body_tail"] == data[-16:].decode()
