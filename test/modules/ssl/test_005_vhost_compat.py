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


class TestVhostCompatAuthonly:
    """Under 'authonly' SSLVHostSNIPolicy, vhosts with different server
    certificates but identical authentication settings are compatible.
    This is the regression fix for PR 69743: the 'secure' default was
    too strict for deployments that intentionally use different certs on
    the same IP:port."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, request):
        has_policy = env.has_directive("SSLVHostSNIPolicy")
        if not has_policy:
            request.applymarker(pytest.mark.xfail(
                reason="SSLVHostSNIPolicy not available", strict=False))
        alt_domain = f"test2.{env.http_tld}"
        alt_creds = env.ca.issue_cert(
            CertificateSpec(name="ssl005-authonly", domains=[alt_domain],
                            key_type='rsa2048'))

        for name in ("test1", "test2"):
            doc = os.path.join(env.server_dir, "htdocs", name)
            os.makedirs(doc, exist_ok=True)
            with open(os.path.join(doc, "index.html"), "w") as f:
                f.write(f"vhost {name}\n")

        extras = {
            f"test1.{env.http_tld}": "LogLevel ssl:debug",
            alt_domain: f"""
            LogLevel ssl:debug
            SSLCertificateFile "{alt_creds.cert_file}"
            SSLCertificateKeyFile "{alt_creds.pkey_file}"
            """,
        }
        if has_policy:
            extras['base'] = 'SSLVHostSNIPolicy authonly'
        conf = HttpdConf(env, extras=extras)
        conf.add_vhost_test1()
        conf.start_vhost(domains=[alt_domain],
                         port=env.https_port,
                         doc_root="htdocs/test2",
                         with_certificates=False)
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    # Under 'authonly', a Host: mismatch to a vhost with a different
    # certificate but same auth settings is allowed.  This is the
    # regression that PR 69743 fixed.
    def test_ssl_005_10(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        alt_host = f"test2.{env.http_tld}"
        r = env.curl_get(url, options=[
            "--http1.1", "-H", f"Host: {alt_host}",
        ])
        assert r.exit_code == 0, f"curl failed: {r.stderr}"
        assert r.response["status"] == 200

    # Same check without SNI — should also be allowed under 'authonly'
    # when only the certificate differs.
    def test_ssl_005_11(self, env):
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
        assert re.search(r'HTTP/1\.[01] 200', r.stdout), \
            f"expected 200 in response, got: {r.stdout[:500]}"


class TestVhostCompatAuthonlyAuth:
    """Under 'authonly' SSLVHostSNIPolicy, vhosts with different client
    authentication settings (different SSLCACertificateFile) must still
    be blocked — this is the core CVE-2025-23048 scenario."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env, request):
        has_policy = env.has_directive("SSLVHostSNIPolicy")
        if not has_policy:
            request.applymarker(pytest.mark.xfail(
                reason="SSLVHostSNIPolicy not available", strict=False))
        alt_domain = f"test2.{env.http_tld}"

        sub_ca = env.ca.issue_cert(
            CertificateSpec(name="ssl005-subca"))
        sub_ca_file = os.path.join(env.server_dir, "ssl005-subca.pem")
        sub_ca.save_cert_pem(sub_ca_file)

        for name in ("test1", "test2"):
            doc = os.path.join(env.server_dir, "htdocs", name)
            os.makedirs(doc, exist_ok=True)
            with open(os.path.join(doc, "index.html"), "w") as f:
                f.write(f"vhost {name}\n")

        extras = {
            f"test1.{env.http_tld}": f"""
            LogLevel ssl:debug
            SSLVerifyClient optional
            SSLCACertificateFile "{env.ca.cert_file}"
            """,
            alt_domain: f"""
            LogLevel ssl:debug
            SSLVerifyClient optional
            SSLCACertificateFile "{sub_ca_file}"
            """,
        }
        if has_policy:
            extras['base'] = 'SSLVHostSNIPolicy authonly'
        conf = HttpdConf(env, extras=extras)
        conf.add_vhost_test1()
        conf.start_vhost(domains=[alt_domain],
                         port=env.https_port,
                         doc_root="htdocs/test2")
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

        env.httpd_error_log.add_ignored_lognos(["AH02032"])

    # Even under 'authonly', different SSLCACertificateFile between
    # vhosts must return 421.
    def test_ssl_005_20(self, env):
        url = env.mkurl("https", "test1", "/index.html")
        alt_host = f"test2.{env.http_tld}"
        r = env.curl_get(url, options=[
            "--http1.1", "-H", f"Host: {alt_host}",
        ])
        assert r.exit_code == 0, f"curl failed: {r.stderr}"
        assert r.response["status"] == 421

    # Without SNI, same scenario — must also be 421.
    def test_ssl_005_21(self, env):
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
