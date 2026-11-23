import pytest

from pyhttpd.conf import HttpdConf
from .fcgi_faker import FcgiFaker


class TestProxyFcgiSetEnvIf:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def _class_scope(cls, env):
        env.require(env.has_shared_module("proxy_fcgi"), "mod_proxy_fcgi not available",
                    dep="mod_proxy_fcgi",
                    detected=f"no mod_proxy_fcgi.so in {env.libexec_dir}")
        faker = FcgiFaker(env.http_port2)
        faker.start()
        backend = f"fcgi://127.0.0.1:{env.http_port2}/"
        conf = HttpdConf(env)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"],
                         port=env.http_port, with_ssl=False)
        conf.add([
            "<Location /capture/>",
            f"  ProxyPass {backend}",
            "  ProxyFCGISetEnvIf \"reqenv('REQUEST_URI') =~ m#^/capture/(.+)#\" TEST_CAPTURED \"$1\"",
            "  ProxyFCGISetEnvIf true TEST_NOCAP \"[$1]\"",
            "</Location>",
            "<Location /nocap/>",
            f"  ProxyPass {backend}",
            "  ProxyFCGISetEnvIf true TEST_NOCAP \"[$1]\"",
            "</Location>",
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        yield
        faker.stop()

    # $1 after a condition that captured nothing is empty, not the capture
    # of the previous ProxyFCGISetEnvIf nor uninitialized memory (BZ 70369)
    @pytest.mark.parametrize("path, expected", [
        ("/capture/abc", {"TEST_CAPTURED": "abc", "TEST_NOCAP": "[]"}),
        ("/nocap/abc", {"TEST_NOCAP": "[]"}),
    ])
    def test_proxy_13_01_expr_no_capture(self, env, path, expected):
        url = env.mkurl("http", "test1", path)
        r = env.curl_get(url, 5)
        assert r.exit_code == 0, f"{r}"
        assert r.response["status"] == 200
        assert r.json == expected
