import os
import pytest

from pyhttpd.conf import HttpdConf


class TestSNI:
    LOG_FILE = "test_sni.log"

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        conf = HttpdConf(env, extras={
            "base":
                f'CustomLog logs/{self.LOG_FILE} "%{{SSL_TLS_SNI}}x"'
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    # check sni logging characters
    def test_ssl_001_01(self, env):
        log_path = os.path.join(env.server_logs_dir, self.LOG_FILE)

        open(log_path, 'w').close()
        sni = "httpd\x01\n2024\".org"

        r = env.run(args=[
            'openssl', 's_client',
            '-connect', f"localhost:{env.https_port}",
            '-servername', sni
        ], intext="GET / HTTP/1.1\n\n")
        assert r.exit_code == 0

        with open(log_path, 'rb') as f:
            log_content = f.read()

        assert sni.encode() not in log_content, \
            f"found unescaped characters in {self.LOG_FILE}.log"
