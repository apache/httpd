import os
import re

from .env import H3Conf, known_bug


class TestStartup:

    def test_h3_010_01_no_h3_vhost(self, env):
        H3Conf(env).add_vhost_test1().install()
        rc = env.apache_restart()
        env.httpd_error_log.ignore_recent(matches=[r'.*no host serves HTTP/3'])
        known_bug(rc != 0, "httpd does not start with mod_http3 loaded and "
                  "no H3 vhost")
        assert env.alt_svc() is None

    def test_h3_010_02_bind(self, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0
        assert env.wait_udp_port(env.https_port)
        assert env.apache_stop() == 0
        assert env.wait_udp_port(env.https_port, in_use=False)

    def test_h3_010_03_no_ssl(self, env):
        # h3 in Protocols on a host without SSLEngine: no certificate to serve
        conf = H3Conf(env)
        conf.start_vhost(domains=[env.h3_domain], port=env.http_port,
                         doc_root="htdocs/test1")
        conf.add_h3_protocol()
        conf.end_vhost()
        conf.install()
        assert env.apache_fail() == 0
        error = r'.*no host serves HTTP/3'
        assert env.httpd_error_log.scan_recent(re.compile(error), timeout=5)
        env.httpd_error_log.ignore_recent(matches=[error])

    def test_h3_010_05_cert_unusable(self, env):
        # loaded with mod_ssl's at startup, not by each child
        junk = os.path.join(env.gen_dir, "h3-junk.pem")
        with open(junk, "w") as fd:
            fd.write("not a certificate\n")
        H3Conf(env).add_h3_vhost(directives=[
            f"SSLCertificateFile {junk}",
            f"SSLCertificateKeyFile {junk}",
        ]).install()
        assert env.apache_fail() == 0
        env.httpd_error_log.ignore_recent(matches=[
            r'.*\[(ssl|http3):(error|emerg)\]',
        ])

    def test_h3_010_06_server_scope_port(self, env):
        port = env.free_udp_port()
        conf = H3Conf(env)
        conf.add_h3_protocol()
        conf.add(f"H3Port {port}")
        conf.add_vhost_test1().install()
        assert env.apache_restart() == 0
        assert env.wait_udp_port(port)
        assert env.alt_svc() == f'h3=":{port}"; ma=86400; persist=1'

    def test_h3_010_07_server_scope_default_port(self, env):
        conf = H3Conf(env)
        conf.add_h3_protocol()
        conf.add_vhost_test1().install()
        assert env.apache_restart() == 0
        known_bug(not env.wait_udp_port(env.https_port, timeout=2),
                  "at server scope without H3Port every child binds an "
                  "ephemeral UDP port")
