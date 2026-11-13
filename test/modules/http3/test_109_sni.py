import re

import pytest

from .env import H3Conf


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

    @staticmethod
    def _get_cert_cn(r):
        # %{certs} needs curl 7.88+ and certinfo in the QUIC TLS backend.
        m = re.search(r'Subject:\s*CN\s*=\s*([^\s,/]+)', r.stdout)
        if m is None:
            pytest.skip("curl prints no certificate subject for HTTP/3")
        return m.group(1)

    @staticmethod
    def _get(env, url, insecure=False):
        # --http3-only: no fallback to TLS over TCP, where mod_ssl does SNI.
        r = env.curl_get(url, insecure=insecure,
                         options=["--http3-only", "-w", "%{certs}"])
        assert r.exit_code == 0, f"{r}"
        assert r.response["protocol"] == "HTTP/3", f"{r}"
        return r

    def test_h3_109_01_sni_default(self, env):
        """The default vhost serves its own certificate."""
        env.require_curl_http3()
        r = self._get(env, env.mkurl("https", "test1", "/001.html"))
        cn = self._get_cert_cn(r)
        assert cn == env.h3_domain, f"expected CN={env.h3_domain}, got {cn}"

    def test_h3_109_02_sni_other_vhost(self, env):
        """A different vhost gets its own certificate via SNI."""
        env.require_curl_http3()
        url = f"https://{env.other_domain}:{env.https_port}/001.html"
        r = self._get(env, url, insecure=True)
        cn = self._get_cert_cn(r)
        assert cn == env.other_domain, \
            f"expected CN={env.other_domain}, got {cn}"
