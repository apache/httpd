import pytest

from .env import H3Conf

# each of these runs in the post_read_request hook
CASES = {
    "setenvif": ([], lambda e: e.get("H3_SETENVIF") == "1"),
    "unique_id": ([], lambda e: bool(e.get("UNIQUE_ID"))),
    "header_early": ([], lambda e: e.get("HTTP_X_EARLY") == "1"),
    "remoteip": ([("x-forwarded-for", "10.1.2.3")],
                 lambda e: e.get("REMOTE_ADDR") == "10.1.2.3"),
}


class TestHooks:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost(directives=[
            "SetEnvIf Request_URI ^/cgi/ H3_SETENVIF=1",
            "RequestHeader set X-Early 1 early",
            "RemoteIPHeader X-Forwarded-For",
            "RemoteIPInternalProxy 127.0.0.1",
        ]).install()
        assert env.apache_restart() == 0

    @pytest.mark.parametrize("name", list(CASES))
    def test_h3_105_01_post_read_request(self, env, name):
        headers, check = CASES[name]
        url = f"https://{env.h3_domain}:{env.https_port}/cgi/env.py"
        opts = ["--http1.1"]
        for k, v in headers:
            opts += ["-H", f"{k}: {v}"]
        tcp = env.curl_get(url, options=opts)
        assert check(tcp.json), f"{name} not seen over HTTP/1.1: {tcp.json}"
        r = env.h3_client().get("/cgi/env.py", headers=headers)
        assert r.status == 200, f"{r}"
        assert check(r.json), f"{name} not seen over HTTP/3: {r.json}"
