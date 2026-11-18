import pytest

from pyhttpd.certs import CertificateSpec
from .env import H2Conf, H2TestEnv


# BZ 70284: "Require ssl-verify-client" denied a client certificate that
# the connection had already verified, whenever the request came in over
# an HTTP/2 secondary (stream) connection. ssl_authz_verify_client_check()
# looked up the SSLConnRec on r->connection directly instead of falling
# back to r->connection->master the way every other mod_ssl hook that
# touches a request already does (see ssl_hook_Access(),
# modssl_request_is_tls()), so it always found no SSLConnRec at all on an
# h2 stream and denied access outright, even though SSL_CLIENT_VERIFY
# itself already read SUCCESS for the same request.
#
# SSLVerifyClient is "optional" at the server level here, not "require":
# that is the documented use case for the "ssl-verify-client" provider
# (see mod_ssl.xml, "Require ssl-verify-client" section) and it is what
# makes the <Location> authz check below the thing that actually grants
# or denies access, rather than the TLS handshake itself -- with
# SSLVerifyClient require, a request without a certificate would never
# even complete its handshake, and the authz provider's own logic (the
# part this bug was in) would never be reached for that case.
@pytest.mark.skipif(condition=H2TestEnv.is_unsupported(), reason="mod_http2 not supported here")
class TestSslVerifyClientAuthz:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        domain = f"ssl.{env.http_tld}"
        conf = H2Conf(env, extras={
            'base': [
                f"SSLCACertificateFile \"{env.ca.cert_file}\"",
            ],
            domain: [
                "Protocols h2 http/1.1",
                "SSLVerifyClient optional",
                "SSLVerifyDepth 2",
                "<Location /verify-authz>",
                "    Require ssl-verify-client",
                "</Location>",
            ],
        })
        conf.add_vhost(domains=[domain], port=env.https_port)
        conf.install()
        env.mkpath(f"{env.server_dir}/htdocs/verify-authz")
        with open(f"{env.server_dir}/htdocs/verify-authz/index.html", "w") as f:
            f.write("secret\n")
        assert env.apache_restart() == 0

    @pytest.fixture(scope='class')
    def client_creds(self, env):
        return env.ca.issue_cert(
            CertificateSpec(name="verify-authz-client", client=True))

    # baseline: the same certificate is granted over HTTP/1.1, as before
    # this fix (ssl_authz_verify_client_check never had a bug here).
    def test_h2_112_01(self, env, client_creds):
        url = env.mkurl("https", "ssl", "/verify-authz/index.html")
        r = env.curl_get(url, options=[
            "--http1.1", "--cert", client_creds.cert_file,
            "--key", client_creds.pkey_file])
        assert r.response
        assert "HTTP/1.1" == r.response["protocol"]
        assert 200 == r.response["status"]

    # the actual regression: same certificate, same connection-level
    # verification, but routed over an HTTP/2 stream -- must be granted
    # exactly like HTTP/1.1 above, not denied for lack of a SSLConnRec
    # that only exists on the stream's master connection.
    def test_h2_112_02(self, env, client_creds):
        url = env.mkurl("https", "ssl", "/verify-authz/index.html")
        r = env.curl_get(url, options=[
            "--http2", "--cert", client_creds.cert_file,
            "--key", client_creds.pkey_file])
        assert r.response
        assert "HTTP/2" == r.response["protocol"]
        assert 200 == r.response["status"]

    # negative control, on the same HTTP/2 stream path as the fix: a
    # client that presents no certificate at all must still be denied by
    # the authz provider itself (SSL_get_peer_certificate() returns NULL),
    # not accidentally let through because modssl_request_is_tls() now
    # finds the master connection's SSLConnRec.
    def test_h2_112_03(self, env):
        url = env.mkurl("https", "ssl", "/verify-authz/index.html")
        r = env.curl_get(url, options=["--http2"])
        assert r.response
        assert "HTTP/2" == r.response["protocol"]
        assert 403 == r.response["status"]
        env.httpd_error_log.ignore_recent(
            lognos=[
                "AH01630"   # client denied by server configuration
            ]
        )
