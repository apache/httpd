import re

from .env import H3Conf, known_bug


class TestAltSvc:

    def test_h3_012_01_default(self, env):
        H3Conf(env).add_h3_vhost().install()
        assert env.apache_restart() == 0
        assert env.alt_svc() == f'h3=":{env.https_port}"; ma=86400; persist=1'

    def test_h3_012_02_off(self, env):
        H3Conf(env).add_h3_vhost(directives=["H3AltSvc off"]).install()
        assert env.apache_restart() == 0
        assert env.alt_svc() is None
        assert env.wait_udp_port(env.https_port)

    def test_h3_012_03_max_age(self, env):
        H3Conf(env).add_h3_vhost(directives=["H3AltSvcMaxAge 3600"]).install()
        assert env.apache_restart() == 0
        assert env.alt_svc() == f'h3=":{env.https_port}"; ma=3600; persist=1'

    def test_h3_012_04_port(self, env):
        port = env.free_udp_port()
        H3Conf(env).add_h3_vhost(directives=[f"H3Port {port}"]).install()
        assert env.apache_restart() == 0
        assert env.alt_svc() == f'h3=":{port}"; ma=86400; persist=1'
        assert env.wait_udp_port(port)
        assert not env.udp_port_in_use(env.https_port)

    def test_h3_012_05_other_vhosts(self, env):
        conf = H3Conf(env)
        conf.add_h3_vhost()
        conf.add_vhost(domains=[f"test2.{env.http_tld}"],
                       port=env.https_port, doc_root="htdocs/test1")
        conf.add_vhost(domains=[env.h3_domain], port=env.http_port,
                       doc_root="htdocs/test1")
        conf.install()
        assert env.apache_restart() == 0
        assert env.alt_svc() is not None
        assert env.alt_svc(domain=f"test2.{env.http_tld}") is None
        assert env.alt_svc(scheme="http") is None

    def test_h3_012_06_port_taken(self, env):
        port = env.free_udp_port()
        with env.hold_udp_port(port):
            H3Conf(env).add_h3_vhost(directives=[f"H3Port {port}"]).install()
            assert env.apache_restart() == 0
            alt_svc = env.alt_svc()
            assert env.apache_stop() == 0
        env.httpd_error_log.ignore_recent(
            matches=[rf'.*\[http3:(error|warn)\].*\b{port}\b'])
        known_bug(alt_svc is not None, "Alt-Svc is sent when the UDP port "
                  "is held by another process")

    def test_h3_012_07_port_taken_logged(self, env):
        port = env.free_udp_port()
        with env.hold_udp_port(port):
            H3Conf(env).add_h3_vhost(directives=[f"H3Port {port}"]).install()
            assert env.apache_restart() == 0
            pattern = re.compile(rf'.*\[http3:(error|warn)\].*\b{port}\b')
            try:
                logged = env.httpd_error_log.scan_recent(pattern, timeout=3)
            except TimeoutError:
                logged = False
            assert env.apache_stop() == 0
        env.httpd_error_log.ignore_recent(matches=[pattern.pattern])
        known_bug(not logged, "a UDP port held by another process is "
                  "retried silently")
