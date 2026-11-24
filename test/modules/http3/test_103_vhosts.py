import pytest

from .env import H3Conf, known_bug


class TestVhosts:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        conf = H3Conf(env)
        conf.add_h3_vhost(directives=["Header always set X-Vhost test1"])
        conf.start_vhost(domains=[f"test2.{env.http_tld}"],
                         port=env.https_port, doc_root="htdocs/test1")
        conf.add("Header always set X-Vhost test2")
        conf.end_vhost()
        conf.start_vhost(domains=[env.other_domain], port=env.https_port,
                         doc_root="htdocs/test1")
        conf.add(["Header always set X-Vhost other",
                  "SSLProtocol TLSv1.3"])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    def authority(self, env, name):
        return f"{name}.{env.http_tld}:{env.https_port}"

    def test_h3_103_01_authority(self, env):
        client = env.h3_client()
        r = client.get("/", authority=self.authority(env, "test1"))
        assert r.header("x-vhost") == "test1", f"{r}"
        r = client.get("/", authority=self.authority(env, "test2"))
        assert r.header("x-vhost") == "test2", f"{r}"

    def test_h3_103_02_unknown_authority(self, env):
        r = env.h3_client().get("/", authority=self.authority(env, "nowhere"))
        assert r.status == 200, f"{r}"
        assert r.header("x-vhost") == "test1"

    def test_h3_103_03_host_mismatch(self, env):
        # RFC 9114 4.3.1: a Host that differs from :authority is malformed
        r = env.h3_client().get("/", authority=self.authority(env, "test1"),
                                headers=[("host", self.authority(env, "test2"))])
        known_bug(r.status == 200,
                  f"Host overrides :authority (served {r.header('x-vhost')})")
        assert r.status == 400 or r.reset is not None, f"{r}"

    def test_h3_103_04_misdirected(self, env):
        url = f"https://{env.h3_domain}:{env.https_port}/"
        tcp = env.curl_get(url, options=[
            "--http1.1", "-H", f"Host: {self.authority(env, 'other')}"])
        assert tcp.response["status"] == 421, f"{tcp.response}"
        env.httpd_error_log.ignore_recent(lognos=["AH02032"])
        r = env.h3_client().get("/", authority=self.authority(env, "other"))
        known_bug(r.status == 200, "a vhost whose TLS setup differs from the "
                  "HTTP/3 one is served instead of 421")
        assert r.status == 421, f"{r}"
