import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestSSI:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                'AddOutputFilter INCLUDES .html',
                '<Location "/ssi">',
                '  Options +Includes',
                '</Location>',
            ],
        })
        conf.add_vhost_cgi(
            proxy_self=True, h2proxy_self=True
        ).add_vhost_test1(
            proxy_self=True, h2proxy_self=True
        ).install()
        assert env.apache_restart() == 0

    # SSI test from https://bz.apache.org/bugzilla/show_bug.cgi?id=66483
    def test_h2_007_01(self, env):
        url = env.mkurl("https", "cgi", "/ssi/test.html")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.stdout == '''<!doctype html>
<html>
<head><meta charset="UTF-8"></head>
<body>
    test<br>
    Hello include<br>

    hello<br>
</body>
</html>
''' , f'{r}'

