import pytest

from pyhttpd.certs import CertificateSpec

from .env import H3Conf, known_bug


@pytest.fixture(scope="module")
def client_cert(env):
    return env.ca.issue_cert(CertificateSpec(name="h3-client", client=True))


def tcp_status(env, path, client_cert=None):
    opts = ["--http1.1"]
    if client_cert:
        opts += ["--cert", client_cert.cert_file, "--key", client_cert.pkey_file]
    r = env.curl_get(f"https://{env.h3_domain}:{env.https_port}{path}",
                     options=opts)
    return r.response["status"] if r.exit_code == 0 else None


class TestDirAccess:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost(directives=[
            f"SSLCACertificateFile {env.ca.cert_file}",
            "SSLVerifyClient optional",
            "<Location /sslrequire>",
            "  SSLRequire %{SSL_CLIENT_VERIFY} eq \"SUCCESS\"",
            "</Location>",
            "<Location /authz>",
            "  Require ssl-verify-client",
            "</Location>",
            "<Location /requiressl>",
            "  SSLRequireSSL",
            "</Location>",
        ]).install()
        assert env.apache_restart() == 0

    def test_h3_106_01_sslrequire(self, env):
        assert tcp_status(env, "/sslrequire/") == 403
        r = env.h3_client().get("/sslrequire/")
        env.httpd_error_log.ignore_recent(lognos=["AH02229"])
        known_bug(r.status != 403, f"SSLRequire is skipped, got {r.status}")

    def test_h3_106_02_require_verify_client(self, env, client_cert):
        assert tcp_status(env, "/authz/") == 403
        assert tcp_status(env, "/authz/", client_cert) != 403
        r = env.h3_client().get("/authz/")
        env.httpd_error_log.ignore_recent(lognos=["AH01630"])
        assert r.status == 403, f"{r}"

    def test_h3_106_03_require_verify_client_cert(self, env, client_cert):
        r = env.h3_client(client_cert=client_cert).get("/authz/")
        env.httpd_error_log.ignore_recent(lognos=["AH01630"])
        known_bug(r.status == 403, "a client certificate cannot be used "
                  "over HTTP/3")

    def test_h3_106_04_requiressl(self, env):
        assert tcp_status(env, "/requiressl/") == 404
        r = env.h3_client().get("/requiressl/")
        env.httpd_error_log.ignore_recent(lognos=["AH02219"])
        known_bug(r.status == 403, "SSLRequireSSL refuses HTTP/3 requests")
        assert r.status == 404, f"{r}"


class TestServerVerifyClient:

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        H3Conf(env).add_h3_vhost(directives=[
            f"SSLCACertificateFile {env.ca.cert_file}",
            "SSLVerifyClient require",
        ]).install()
        assert env.apache_restart() == 0

    def test_h3_106_10_no_cert(self, env, client_cert):
        assert tcp_status(env, "/", client_cert) == 200
        assert tcp_status(env, "/") is None
        env.httpd_error_log.ignore_recent(lognos=["AH10373"])
        r = env.h3_client().get("/")
        known_bug(r.status == 200, "SSLVerifyClient require does not apply "
                  "to HTTP/3")
