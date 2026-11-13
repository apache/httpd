import os
import re

import pytest

from pyhttpd.certs import CertificateSpec
from pyhttpd.conf import HttpdConf


class TestVhostCompatSecure:
    """Under the default 'secure' SSLVHostSNIPolicy, requests routed to a
    virtual host with different SSL parameters (certificate or auth
    settings) than the handshake host are rejected with 421."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        alt_domain = f"test2.{env.http_tld}"
        alt_creds = env.ca.issue_cert(
            CertificateSpec(name="ssl005-alt", domains=[alt_domain],
                            key_type='rsa2048'))

        for name in ("test1", "test2"):
            doc = os.path.join(env.server_dir, "htdocs", name)
            os.makedirs(doc, exist_ok=True)
            with open(os.path.join(doc, "index.html"), "w") as f:
                f.write(f"vhost {name}\n")

        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": "LogLevel ssl:debug",
            alt_domain: f"""
            LogLevel ssl:debug
            SSLCertificateFile "{alt_creds.cert_file}"
            SSLCertificateKeyFile "{alt_creds.pkey_file}"
            """,
        })
        conf.add_vhost_test1()
        conf.start_vhost(domains=[alt_domain],
                         port=env.https_port,
                         doc_root="htdocs/test2",
                         with_certificates=False)
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

        env.httpd_error_log.add_ignored_lognos(["AH02032"])

    # SNI selects a vhost and Host: names a different one with a
    # different certificate.  Must return 421.
    def test_ssl_005_01(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        alt_host = f"test2.{env.http_tld}"
        r = env.curl_get(url, options=[
            "--http1.1", "-H", f"Host: {alt_host}",
        ])
        assert r.exit_code == 0, f"curl failed: {r.stderr}"
        assert r.response["status"] == 421

    # Same vhost for SNI and Host: — must succeed.
    def test_ssl_005_02(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_get(url, options=["--http1.1"])
        assert r.exit_code == 0, f"curl failed: {r.stderr}"
        assert r.response["status"] == 200

    # No SNI at all, with Host: selecting a vhost whose SSL parameters
    # differ from the default (handshake) host.  Must return 421.
    def test_ssl_005_03(self, env):
        alt_host = f"test2.{env.http_tld}"
        r = env.run([
            'openssl', 's_client',
            '-connect', f'127.0.0.1:{env.https_port}',
            '-CAfile', env.ca.cert_file,
            '-noservername',
            '-tls1_3',
            '-ign_eof',
        ], intext=(
            f"GET /index.html HTTP/1.1\r\n"
            f"Host: {alt_host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ))
        assert r.exit_code == 0, f"openssl s_client failed: {r.stderr}"
        assert re.search(r'HTTP/1\.[01] 421', r.stdout), \
            f"expected 421 in response, got: {r.stdout[:500]}"

    # No SNI, but Host: matches the default (handshake) vhost — must
    # succeed because the SSL parameters are the same.
    def test_ssl_005_04(self, env):
        default_host = f"test1.{env.http_tld}"
        r = env.run([
            'openssl', 's_client',
            '-connect', f'127.0.0.1:{env.https_port}',
            '-CAfile', env.ca.cert_file,
            '-noservername',
            '-tls1_3',
            '-ign_eof',
        ], intext=(
            f"GET /index.html HTTP/1.1\r\n"
            f"Host: {default_host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ))
        assert r.exit_code == 0, f"openssl s_client failed: {r.stderr}"
        assert re.search(r'HTTP/1\.[01] 200', r.stdout), \
            f"expected 200 in response, got: {r.stdout[:500]}"

    # TLS 1.3 session resumption: establish a session with vhost A, then
    # resume it without SNI while Host: names vhost B (different SSL
    # config).  The resumed connection must also be rejected with 421.
    def test_ssl_005_05(self, env):
        default_host = f"test1.{env.http_tld}"
        alt_host = f"test2.{env.http_tld}"
        sess_dir = os.path.join(env.gen_dir, "ssl005")
        os.makedirs(sess_dir, exist_ok=True)
        sess_file = os.path.join(sess_dir, "session.pem")

        r = env.run([
            'openssl', 's_client',
            '-connect', f'127.0.0.1:{env.https_port}',
            '-CAfile', env.ca.cert_file,
            '-servername', default_host,
            '-tls1_3',
            '-sess_out', sess_file,
            '-ign_eof',
        ], intext=(
            f"GET /index.html HTTP/1.1\r\n"
            f"Host: {default_host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ))
        assert r.exit_code == 0, f"session setup failed: {r.stderr}"
        assert os.path.isfile(sess_file), "no session ticket saved"

        r = env.run([
            'openssl', 's_client',
            '-connect', f'127.0.0.1:{env.https_port}',
            '-CAfile', env.ca.cert_file,
            '-noservername',
            '-tls1_3',
            '-sess_in', sess_file,
            '-ign_eof',
        ], intext=(
            f"GET /index.html HTTP/1.1\r\n"
            f"Host: {alt_host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ))
        assert r.exit_code == 0, f"resumed connection failed: {r.stderr}"
        assert re.search(r'HTTP/1\.[01] 421', r.stdout), \
            f"expected 421 on resumed connection, got: {r.stdout[:500]}"


# The policies of SSLVHostSNIPolicy, each with the classes of difference
# between two vhosts which it blocks; this is the table in the
# documentation of the directive.  "default" is the server without the
# directive, which is documented to behave as "secure".
POLICIES = {
    "default": ("server", "client"),
    "strict": ("vhost", "server", "client"),
    "secure": ("server", "client"),
    "authonly": ("client",),
    "insecure": (),
}

# The vhosts tested against the handshake vhost, by the class of the
# difference in their SSL configuration: "vhost" for none at all,
# "server" for the server certificate/key and the protocol/cipher
# restrictions, "client" for the client verification and authentication
# settings.  Each name gets a vhost of its own with the given directives,
# in which {cert}, {key} and {ca} are replaced; other than "test1", the
# handshake vhost itself, which no policy blocks.
VHOSTS = {
    "test1": (None, None),
    "same": ("vhost", ""),
    "cert": ("server", """
        SSLCertificateFile "{cert}"
        SSLCertificateKeyFile "{key}"
        """),
    "ciphers": ("server", "SSLCipherSuite ECDHE+AESGCM"),
    "protocol": ("server", "SSLProtocol -all +TLSv1.2 +TLSv1.3"),
    "cacert": ("client", 'SSLCACertificateFile "{ca}"'),
    "depth": ("client", "SSLVerifyDepth 7"),
}


@pytest.mark.need_min_apache_version("2.4.66")
@pytest.mark.parametrize("policy", POLICIES, scope="class")
@pytest.mark.parametrize("vhost", VHOSTS)
class TestVhostCompatPolicy:
    """Under each SSLVHostSNIPolicy, a request for a vhost other than
    the handshake one gets a 421 if their SSL configurations differ in a
    way the policy blocks, and is served otherwise."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, policy):
        default_host = f"test1.{env.http_tld}"
        alt_creds = env.ca.issue_cert(
            CertificateSpec(name="ssl005-cert", domains=[f"cert.{env.http_tld}"],
                            key_type='rsa2048'))
        sub_ca = env.ca.issue_cert(CertificateSpec(name="ssl005-subca"))
        sub_ca_file = os.path.join(env.server_dir, "ssl005-subca.pem")
        sub_ca.save_cert_pem(sub_ca_file)

        conf = HttpdConf(env, extras={
            'base': "" if policy == "default"
                    else f"SSLVHostSNIPolicy {policy}",
        })
        conf.add_vhost_test1()
        for name, (_, directives) in VHOSTS.items():
            if directives is None:
                continue
            conf.start_vhost(domains=[f"{name}.{env.http_tld}"],
                             port=env.https_port,
                             doc_root="htdocs/test1",
                             with_certificates=False)
            # The certificate of the handshake vhost, which a later
            # SSLCertificateFile in the directives replaces.
            if name != "cert":
                for cred in env.get_credentials_for_name(default_host):
                    conf.add_certificate(cred.cert_file, cred.pkey_file)
            conf.add(directives.format(cert=alt_creds.cert_file,
                                       key=alt_creds.pkey_file,
                                       ca=sub_ca_file))
            conf.end_vhost()
        conf.install()
        # AH01909: the vhosts use a certificate without their name in it.
        env.httpd_error_log.add_ignored_lognos(["AH01909", "AH02032"])
        assert env.apache_restart() == 0

    @staticmethod
    def expected(policy, vhost):
        return 421 if VHOSTS[vhost][0] in POLICIES[policy] else 200

    # SNI selects the handshake vhost, Host: names the other one.
    def test_ssl_005_10(self, env, policy, vhost):
        url = env.mkurl("https", "test1", "/index.html")
        r = env.curl_get(url, options=[
            "--http1.1", "-H", f"Host: {vhost}.{env.http_tld}",
        ])
        assert r.exit_code == 0, f"curl failed: {r.stderr}"
        assert r.response["status"] == self.expected(policy, vhost)

    # No SNI, so the default vhost is the handshake one.
    def test_ssl_005_11(self, env, policy, vhost):
        r = env.run([
            'openssl', 's_client',
            '-connect', f'127.0.0.1:{env.https_port}',
            '-CAfile', env.ca.cert_file,
            '-noservername',
            '-tls1_3',
            '-ign_eof',
        ], intext=(
            f"GET /index.html HTTP/1.1\r\n"
            f"Host: {vhost}.{env.http_tld}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ))
        assert r.exit_code == 0, f"openssl s_client failed: {r.stderr}"
        status = self.expected(policy, vhost)
        assert re.search(rf'HTTP/1\.[01] {status}', r.stdout), \
            f"expected {status} in response, got: {r.stdout[:500]}"
