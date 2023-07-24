import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestProxyFwd:

    @classmethod
    def config_fwd_proxy(cls, env, h2_enabled=False):
        conf = H2Conf(env, extras={
            'base': [
                f'Listen {env.proxy_port}',
                'Protocols h2c http/1.1',
                'LogLevel proxy_http2:trace2 proxy:trace2',
            ],
        })
        conf.add_vhost_cgi(proxy_self=False, h2proxy_self=False)
        conf.start_vhost(domains=[f"test1.{env.http_tld}"],
                         port=env.proxy_port, with_ssl=True)
        conf.add([
            'Protocols h2c http/1.1',
            'ProxyRequests on',
            f'H2ProxyRequests {"on" if h2_enabled else "off"}',
        ])
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(cls, env):
        cls.config_fwd_proxy(env)

    # test the HTTP/1.1 setup working
    def test_h2_503_01_proxy_fwd_h1(self, env):
        url = f'http://localhost:{env.http_port}/hello.py'
        proxy_host = f'test1.{env.http_tld}'
        options = [
            '--proxy', f'https://{proxy_host}:{env.proxy_port}',
            '--resolve', f'{proxy_host}:{env.proxy_port}:127.0.0.1',
            '--proxy-cacert', f'{env.get_ca_pem_file(proxy_host)}',
        ]
        r = env.curl_get(url, 5, options=options)
        assert r.exit_code == 0, f'{r}'
        assert r.response['status'] == 200
        assert r.json['port'] == f'{env.http_port}'

    def test_h2_503_02_fwd_proxy_h2_off(self, env):
        if not env.curl_is_at_least('8.1.0'):
            pytest.skip(f'need at least curl v8.1.0 for this')
        url = f'http://localhost:{env.http_port}/hello.py'
        proxy_host = f'test1.{env.http_tld}'
        options = [
            '--proxy-http2', '-v',
            '--proxy', f'https://{proxy_host}:{env.proxy_port}',
            '--resolve', f'{proxy_host}:{env.proxy_port}:127.0.0.1',
            '--proxy-cacert', f'{env.get_ca_pem_file(proxy_host)}',
        ]
        r = env.curl_get(url, 5, options=options)
        assert r.exit_code == 0, f'{r}'
        assert r.response['status'] == 404

    # test the HTTP/2 setup working
    def test_h2_503_03_proxy_fwd_h2_on(self, env):
        if not env.curl_is_at_least('8.1.0'):
            pytest.skip(f'need at least curl v8.1.0 for this')
        self.config_fwd_proxy(env, h2_enabled=True)
        url = f'http://localhost:{env.http_port}/hello.py'
        proxy_host = f'test1.{env.http_tld}'
        options = [
            '--proxy-http2', '-v',
            '--proxy', f'https://{proxy_host}:{env.proxy_port}',
            '--resolve', f'{proxy_host}:{env.proxy_port}:127.0.0.1',
            '--proxy-cacert', f'{env.get_ca_pem_file(proxy_host)}',
        ]
        r = env.curl_get(url, 5, options=options)
        assert r.exit_code == 0, f'{r}'
        assert r.response['status'] == 200
        assert r.json['port'] == f'{env.http_port}'
