import re

import pytest

from .env import H3Conf, known_bug


class TestSNI:
    """Verify that the HTTP/3 listener serves the right certificate per SNI."""

    @pytest.fixture(autouse=True, scope="class")
    @classmethod
    def _class_scope(cls, env):
        conf = H3Conf(env)
        conf.add_h3_vhost(directives=["Header always set X-Vhost test1"])
        conf.start_vhost(domains=[env.other_domain],
                         port=env.https_port, doc_root="htdocs/test1")
        conf.add(["Protocols h3 http/1.1",
                  "Header always set X-Vhost other"])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        env.httpd_error_log.ignore_recent(
            matches=[r".*QUIC handshake did not complete.*"])

    @staticmethod
    def _get_cert_cn(r):
        m = re.search(r'Subject:CN\s*=\s*(\S+)', r.stdout)
        return m.group(1) if m else None

    _HANDSHAKE_ERR = [r".*QUIC handshake did not complete.*"]

    def test_h3_108_01_sni_default(self, env):
        """The default vhost serves its own certificate."""
        env.require_curl_http3()
        url = env.mkurl("https", "test1", "/001.html")
        r = env.curl_get(url, options=["--http3", "-w", "%{certs}"])
        env.httpd_error_log.ignore_recent(matches=self._HANDSHAKE_ERR)
        assert r.exit_code == 0, f"{r}"
        cn = self._get_cert_cn(r)
        assert cn is not None, "no certificate CN in curl output"
        assert env.h3_domain in cn or env.http_tld in cn, \
            f"expected CN covering {env.h3_domain}, got {cn}"

    def test_h3_108_02_sni_other_vhost(self, env):
        """A different vhost should get its own certificate via SNI."""
        env.require_curl_http3()
        url = f"https://{env.other_domain}:{env.https_port}/001.html"
        r = env.curl_get(url, insecure=True,
                         options=["--http3", "-w", "%{certs}"])
        env.httpd_error_log.ignore_recent(matches=self._HANDSHAKE_ERR)
        assert r.exit_code == 0, f"{r}"
        cn = self._get_cert_cn(r)
        assert cn is not None, "no certificate CN in curl output"
        known_bug(env.other_domain not in cn,
                  "HTTP/3 serves the listener cert, not the SNI-matched one")
        assert env.other_domain in cn, \
            f"expected CN={env.other_domain}, got {cn}"
