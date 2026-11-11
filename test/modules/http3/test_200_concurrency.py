from concurrent.futures import ThreadPoolExecutor

import pytest

from .env import H3Conf


class TestConcurrency:
    """Test mod_http3 stability under highly concurrent requests."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0

    def test_h3_200_01_concurrent_connections_survive(self, env):
        env.require_curl_http3()
        get_url = env.mkurl("https", "test1", "/001.html")
        post_url = env.mkurl("https", "test1", "/")
        body = b"x" * 512

        def do_get(_i):
            return env.curl_get(get_url, options=["--http3"])

        def do_post(_i):
            return env.curl_raw(
                post_url,
                options=["--http3", "-X", "POST", "--data-binary", body.decode()],
            )

        def do_put(_i):
            return env.curl_raw(
                post_url,
                options=["--http3", "-X", "PUT", "--data-binary", body.decode()],
            )

        rounds = 4
        per_round = 6
        for _ in range(rounds):
            with ThreadPoolExecutor(max_workers=per_round * 3) as pool:
                futures = []
                for i in range(per_round):
                    futures.append(("get", pool.submit(do_get, i)))
                    futures.append(("post", pool.submit(do_post, i)))
                    futures.append(("put", pool.submit(do_put, i)))
                results = [(kind, f.result()) for kind, f in futures]

            for kind, r in results:
                assert r.exit_code == 0, f"{kind}: " + r.stderr + r.stdout
                if kind == "get":
                    assert r.response["status"] == 200
                else:
                    assert r.response["status"] in (200, 404, 405)

        assert env.is_live()
        r = env.curl_get(get_url, options=["--http3"])
        assert r.exit_code == 0, r.stderr + r.stdout
        assert r.response["status"] == 200
