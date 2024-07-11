import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestH2Proxy:

    def test_h2_600_01(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "SetEnvIf Host (.+) X_HOST=$1",
            ]
        })
        conf.add_vhost_cgi(h2proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2proxy/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["json"]["protocol"] == "HTTP/2.0"
        assert r.response["json"]["https"] == "on"
        assert r.response["json"]["ssl_protocol"] != ""
        assert r.response["json"]["h2"] == "on"
        assert r.response["json"]["h2push"] == "off"
        assert r.response["json"]["host"] == f"cgi.{env.http_tld}:{env.https_port}"

    def test_h2_600_02(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "SetEnvIf Host (.+) X_HOST=$1",
                f"ProxyPreserveHost on",
                f"ProxyPass /h2c/ h2c://127.0.0.1:{env.http_port}/",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2c/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["json"]["protocol"] == "HTTP/2.0"
        assert r.response["json"]["https"] == ""
        # the proxied backend sees Host header as passed on front
        assert r.response["json"]["host"] == f"cgi.{env.http_tld}:{env.https_port}"
        assert r.response["json"]["h2_original_host"] == ""

    def test_h2_600_03(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "SetEnvIf Host (.+) X_HOST=$1",
                f"ProxyPreserveHost off",
                f"ProxyPass /h2c/ h2c://127.0.0.1:{env.http_port}/",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2c/hello.py")
        r = env.curl_get(url, 5)
        assert r.response["status"] == 200
        assert r.response["json"]["protocol"] == "HTTP/2.0"
        assert r.response["json"]["https"] == ""
        # the proxied backend sees Host as using in connecting to it
        assert r.response["json"]["host"] == f"127.0.0.1:{env.http_port}"
        assert r.response["json"]["h2_original_host"] == ""

    # check that connection reuse actually happens as configured
    @pytest.mark.parametrize("enable_reuse", [ "on", "off" ])
    def test_h2_600_04(self, env, enable_reuse):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                f"ProxyPassMatch ^/h2proxy/([0-9]+)/(.*)$ "
                f"  h2c://127.0.0.1:$1/$2 enablereuse={enable_reuse} keepalive=on",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", f"/h2proxy/{env.http_port}/hello.py")
        # httpd 2.5.0 disables reuse, not matter the config
        if enable_reuse == "on" and not env.httpd_is_at_least("2.4.60"):
            # reuse is not guaranteed for each request, but we expect some
            # to do it and run on a h2 stream id > 1
            reused = False
            count = 10
            r = env.curl_raw([url] * count, 5)
            response = r.response
            for n in range(count):
                assert response["status"] == 200
                if n == (count - 1):
                    break
                response = response["previous"]
            assert r.json[0]["h2_stream_id"] == "1"
            for n in range(1, count):
                if int(r.json[n]["h2_stream_id"]) > 1:
                    reused = True
                    break
            assert reused
        else:
            r = env.curl_raw([url, url], 5)
            assert r.response["previous"]["status"] == 200
            assert r.response["status"] == 200
            assert r.json[0]["h2_stream_id"] == "1"
            assert r.json[1]["h2_stream_id"] == "1"

    # do some flexible setup from #235 to proper connection selection
    @pytest.mark.parametrize("enable_reuse", [ "on", "off" ])
    def test_h2_600_05(self, env, enable_reuse):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                f"ProxyPassMatch ^/h2proxy/([0-9]+)/(.*)$ "
                f"  h2c://127.0.0.1:$1/$2 enablereuse={enable_reuse} keepalive=on",
            ]
        })
        conf.add_vhost_cgi()
        conf.add([
            f'Listen {env.http_port2}',
            'UseCanonicalName On',
            'UseCanonicalPhysicalPort On'
        ])
        conf.start_vhost(domains=[f'cgi.{env.http_tld}'],
                         port=5004, doc_root="htdocs/cgi")
        conf.add("AddHandler cgi-script .py")
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", f"/h2proxy/{env.http_port}/hello.py")
        url2 = env.mkurl("https", "cgi", f"/h2proxy/{env.http_port2}/hello.py")
        r = env.curl_raw([url, url2], 5)
        assert r.response["previous"]["status"] == 200
        assert int(r.json[0]["port"]) == env.http_port
        assert r.response["status"] == 200
        exp_port = env.http_port if enable_reuse == "on" \
                                    and not env.httpd_is_at_least("2.4.60")\
            else env.http_port2
        assert int(r.json[1]["port"]) == exp_port

    # test X-Forwarded-* headers
    def test_h2_600_06(self, env):
        conf = H2Conf(env, extras={
            f'cgi.{env.http_tld}': [
                "SetEnvIf Host (.+) X_HOST=$1",
                f"ProxyPreserveHost on",
                f"ProxyPass /h2c/ h2c://127.0.0.1:{env.http_port}/",
                f"ProxyPass /h1c/ http://127.0.0.1:{env.http_port}/",
            ]
        })
        conf.add_vhost_cgi(proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h1c/hello.py")
        r1 = env.curl_get(url, 5)
        assert r1.response["status"] == 200
        url = env.mkurl("https", "cgi", "/h2c/hello.py")
        r2 = env.curl_get(url, 5)
        assert r2.response["status"] == 200
        for key in ['x-forwarded-for', 'x-forwarded-host','x-forwarded-server']:
            assert r1.json[key] == r2.json[key], f'{key} differs proxy_http != proxy_http2'

    # lets do some error tests
    def test_h2_600_30(self, env):
        conf = H2Conf(env)
        conf.add_vhost_cgi(h2proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/error?status=500")
        r = env.curl_get(url)
        assert r.exit_code == 0, r
        assert r.response['status'] == 500
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/error?error=timeout")
        r = env.curl_get(url)
        assert r.exit_code == 0, r
        assert r.response['status'] == 408

    # produce an error during response body
    def test_h2_600_31(self, env, repeat):
        conf = H2Conf(env)
        conf.add_vhost_cgi(h2proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/error?body_error=timeout")
        r = env.curl_get(url)
        # depending on when the error is detect in proxying, if may RST the
        # stream (exit_code != 0) or give a 503 response.
        if r.exit_code == 0:
            assert r.response['status'] == 502

    # produce an error, fail to generate an error bucket
    def test_h2_600_32(self, env, repeat):
        conf = H2Conf(env)
        conf.add_vhost_cgi(h2proxy_self=True)
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/error?body_error=timeout&error_bucket=0")
        r = env.curl_get(url)
        # depending on when the error is detect in proxying, if may RST the
        # stream (exit_code != 0) or give a 503 response.
        if r.exit_code == 0:
            assert r.response['status'] in [502, 503]
