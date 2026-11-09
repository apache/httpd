import os
import re

import pytest

from .env import H3Conf, known_bug


class TestStartup:

    def test_h3_010_01_no_h3_vhost(self, env):
        H3Conf(env).add_vhost_test1().install()
        rc = env.apache_restart()
        env.httpd_error_log.ignore_recent(matches=[r'.*check failed: conf'])
        known_bug(rc != 0, "httpd does not start with mod_http3 loaded and "
                  "no H3 vhost")
        assert env.alt_svc() is None

    def test_h3_010_02_bind(self, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0
        assert env.wait_udp_port(env.https_port)
        assert env.apache_stop() == 0
        assert env.wait_udp_port(env.https_port, in_use=False)

    @pytest.mark.parametrize("directive", [
        "H3CertificatePath", "H3CertificateKeyPath"
    ])
    def test_h3_010_03_unreadable(self, env, directive):
        cred = env.get_credentials_for_name(env.h3_domain)[0]
        missing = os.path.join(env.gen_dir, "missing.pem")
        cert = missing if directive == "H3CertificatePath" else cred.cert_file
        key = missing if directive == "H3CertificateKeyPath" else cred.pkey_file
        H3Conf(env).add_h3_vhost(with_certificate=False, directives=[
            f"H3CertificatePath {cert}",
            f"H3CertificateKeyPath {key}",
        ]).install()
        assert env.apache_fail() == 0
        error = rf'.*{directive} not readable: {re.escape(missing)}'
        assert env.httpd_error_log.scan_recent(re.compile(error), timeout=5)
        env.httpd_error_log.ignore_recent(matches=[error])

    def test_h3_010_04_cert_without_key(self, env):
        cred = env.get_credentials_for_name(env.h3_domain)[0]
        H3Conf(env).add_h3_vhost(with_certificate=False, directives=[
            f"H3CertificatePath {cred.cert_file}",
        ]).install()
        assert env.apache_fail() == 0
        env.httpd_error_log.ignore_recent(matches=[r'.*check failed: conf'])

    def test_h3_010_05_cert_unusable(self, env):
        junk = os.path.join(env.gen_dir, "h3-junk.pem")
        with open(junk, "w") as fd:
            fd.write("not a certificate\n")
        H3Conf(env).add_h3_vhost(with_certificate=False, directives=[
            f"H3CertificatePath {junk}",
            f"H3CertificateKeyPath {junk}",
        ]).install()
        rc = env.apache_fail()
        env.httpd_error_log.ignore_recent(matches=[
            r'.*QUIC engine initialization failed',
            r'.*h3_io_listen_start failed',
        ])
        known_bug(rc != 0, "an unusable certificate is only found by each "
                  "child, which then runs without HTTP/3")

    def test_h3_010_06_server_scope_port(self, env):
        port = env.free_udp_port()
        conf = H3Conf(env)
        conf.add_h3_certificate()
        conf.add(f"H3Port {port}")
        conf.add_vhost_test1().install()
        assert env.apache_restart() == 0
        assert env.wait_udp_port(port)
        assert env.alt_svc() == f'h3=":{port}"; ma=86400; persist=1'

    def test_h3_010_07_server_scope_default_port(self, env):
        conf = H3Conf(env)
        conf.add_h3_certificate()
        conf.add_vhost_test1().install()
        assert env.apache_restart() == 0
        known_bug(not env.wait_udp_port(env.https_port, timeout=2),
                  "at server scope without H3Port every child binds an "
                  "ephemeral UDP port")
