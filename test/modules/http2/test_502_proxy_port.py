import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestProxyPort:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env, extras={
            'base': [
                f'Listen {env.proxy_port}',
                'Protocols h2c http/1.1',
                'LogLevel proxy_http2:trace2 proxy:trace2',
            ],
            f'cgi.{env.http_tld}': [
                "Header unset Server",
                "Header always set Server cgi",
            ]
        })
        conf.add_vhost_cgi(proxy_self=False, h2proxy_self=False)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"], port=env.proxy_port)
        conf.add([
            'Protocols h2c',
            'RewriteEngine On',
            'RewriteRule "^/(.*)$" "h2c://%{HTTP_HOST}/$1"[NC,P]',
            'ProxyPassMatch / "h2c://$1/"',
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    # Test PR 65881
    # h2c upgraded request via a dynamic proxy onto another port
    def test_h2_502_01(self, env):
        url = f'http://localhost:{env.http_port}/hello.py'
        r = env.curl_get(url, 5, options=['--http2',
                                          '--proxy', f'localhost:{env.proxy_port}'])
        assert r.response['status'] == 200
        assert r.json['port'] == f'{env.http_port}'
