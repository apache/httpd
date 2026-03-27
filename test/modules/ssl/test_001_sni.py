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

    # tests sni escaped characters
    def test_ssl_001_01(self, env):
        log_path = os.path.join(env.server_logs_dir, self.LOG_FILE)

        open(log_path, 'wb').close()

        env.run(args=[
            'openssl', 's_client',
            '-connect', f"localhost:{env.https_port}",
            '-servername', "httpd\x01\x0a2024\".org",
            '-crlf', '-ign_eof'
        ], intext="GET / HTTP/1.1\n\n")

        with open(log_path, 'rb') as f:
            log_content = f.read()

        assert b'httpd\x01\n2024' not in log_content, \
            f"found unescaped characters in {self.LOG_FILE}.log"
