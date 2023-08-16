import pytest

from .env import H2Conf, H2TestEnv


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestInvalidHeaders:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        H2Conf(env).add_vhost_cgi().install()
        assert env.apache_restart() == 0

    # let the hecho.py CGI echo chars < 0x20 in field name
    # for almost all such characters, the stream returns a 500
    # or in httpd >= 2.5.0 gets aborted with a h2 error
    # cr is handled special
    def test_h2_200_01(self, env):
        url = env.mkurl("https", "cgi", "/hecho.py")
        for x in range(1, 32):
            data = f'name=x%{x:02x}x&value=yz'
            r = env.curl_post_data(url, data)
            if x in [13]:
                assert 0 == r.exit_code, f'unexpected exit code for char 0x{x:02}'
                assert 200 == r.response["status"], f'unexpected status for char 0x{x:02}'
            elif x in [10] or env.httpd_is_at_least('2.5.0'):
                assert 0 == r.exit_code, f'unexpected exit code for char 0x{x:02}'
                assert 500 == r.response["status"], f'unexpected status for char 0x{x:02}'
            else:
                assert 0 != r.exit_code, f'unexpected exit code for char 0x{x:02}'
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH02429"   # Response header name contains invalid characters
            ],
            matches = [
                r'.*malformed header from script \'hecho.py\': Bad header: x.*'
            ]
        )

    # let the hecho.py CGI echo chars < 0x20 in field value
    # for almost all such characters, the stream returns a 500
    # or in httpd >= 2.5.0 gets aborted with a h2 error
    # cr and lf are handled special
    def test_h2_200_02(self, env):
        url = env.mkurl("https", "cgi", "/hecho.py")
        for x in range(1, 32):
            if 9 != x:
                r = env.curl_post_data(url, "name=x&value=y%%%02x" % x)
                if x in [10, 13]:
                    assert 0 == r.exit_code, "unexpected exit code for char 0x%02x" % x
                    assert 200 == r.response["status"], "unexpected status for char 0x%02x" % x
                elif env.httpd_is_at_least('2.5.0'):
                    assert 0 == r.exit_code, f'unexpected exit code for char 0x{x:02}'
                    assert 500 == r.response["status"], f'unexpected status for char 0x{x:02}'
                else:
                    assert 0 != r.exit_code, "unexpected exit code for char 0x%02x" % x
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH02430"   # Response header value contains invalid characters
            ]
        )

    # let the hecho.py CGI echo 0x10 and 0x7f in field name and value
    def test_h2_200_03(self, env):
        url = env.mkurl("https", "cgi", "/hecho.py")
        for h in ["10", "7f"]:
            r = env.curl_post_data(url, "name=x%%%s&value=yz" % h)
            if env.httpd_is_at_least('2.5.0'):
                assert 0 == r.exit_code, f"unexpected exit code for char 0x{h:02}"
                assert 500 == r.response["status"], f"unexpected exit code for char 0x{h:02}"
            else:
                assert 0 != r.exit_code
            r = env.curl_post_data(url, "name=x&value=y%%%sz" % h)
            if env.httpd_is_at_least('2.5.0'):
                assert 0 == r.exit_code, f"unexpected exit code for char 0x{h:02}"
                assert 500 == r.response["status"], f"unexpected exit code for char 0x{h:02}"
            else:
                assert 0 != r.exit_code
        #
        env.httpd_error_log.ignore_recent(
            lognos = [
                "AH02429",  # Response header name contains invalid characters
                "AH02430"   # Response header value contains invalid characters
            ]
        )

    # test header field lengths check, LimitRequestLine
    def test_h2_200_10(self, env):
        conf = H2Conf(env)
        conf.add("""
            LimitRequestLine 1024
            """)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        val = 200*"1234567890"
        url = env.mkurl("https", "cgi", f'/?{val[:1022]}')
        r = env.curl_get(url)
        assert r.response["status"] == 200
        url = env.mkurl("https", "cgi", f'/?{val[:1023]}')
        r = env.curl_get(url)
        # URI too long
        assert 414 == r.response["status"]

    # test header field lengths check, LimitRequestFieldSize (default 8190)
    def test_h2_200_11(self, env):
        conf = H2Conf(env)
        conf.add("""
            LimitRequestFieldSize 1024
            """)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/")
        val = 200*"1234567890"
        # two fields, concatenated with ', '
        # LimitRequestFieldSize, one more char -> 400 in HTTP/1.1
        r = env.curl_get(url, options=[
            '-H', f'x: {val[:500]}', '-H', f'x: {val[:519]}'
        ])
        assert r.exit_code == 0, f'{r}'
        assert r.response["status"] == 200, f'{r}'
        r = env.curl_get(url, options=[
            '--http1.1', '-H', f'x: {val[:500]}', '-H', f'x: {val[:523]}'
        ])
        assert 400 == r.response["status"]
        r = env.curl_get(url, options=[
            '-H', f'x: {val[:500]}', '-H', f'x: {val[:520]}'
        ])
        assert 431 == r.response["status"]

    # test header field count, LimitRequestFields (default 100)
    # see #201: several headers with same name are mered and count only once
    def test_h2_200_12(self, env):
        url = env.mkurl("https", "cgi", "/")
        opt = []
        # curl sends 3 headers itself (user-agent, accept, and our AP-Test-Name)
        for i in range(97):
            opt += ["-H", "x: 1"]
        r = env.curl_get(url, options=opt)
        assert r.response["status"] == 200
        r = env.curl_get(url, options=(opt + ["-H", "y: 2"]))
        assert r.response["status"] == 200

    # test header field count, LimitRequestFields (default 100)
    # different header names count each
    def test_h2_200_13(self, env):
        url = env.mkurl("https", "cgi", "/")
        opt = []
        # curl sends 3 headers itself (user-agent, accept, and our AP-Test-Name)
        for i in range(97):
            opt += ["-H", f"x{i}: 1"]
        r = env.curl_get(url, options=opt)
        assert r.response["status"] == 200
        r = env.curl_get(url, options=(opt + ["-H", "y: 2"]))
        assert 431 == r.response["status"]

    # test "LimitRequestFields 0" setting, see #200
    def test_h2_200_14(self, env):
        conf = H2Conf(env)
        conf.add("""
            LimitRequestFields 20
            """)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/")
        opt = []
        for i in range(21):
            opt += ["-H", "x{0}: 1".format(i)]
        r = env.curl_get(url, options=opt)
        assert 431 == r.response["status"]
        conf = H2Conf(env)
        conf.add("""
            LimitRequestFields 0
            """)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/")
        opt = []
        for i in range(100):
            opt += ["-H", "x{0}: 1".format(i)]
        r = env.curl_get(url, options=opt)
        assert r.response["status"] == 200

    # the uri limits
    def test_h2_200_15(self, env):
        conf = H2Conf(env)
        conf.add("""
            LimitRequestLine 48
            """)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        url = env.mkurl("https", "cgi", "/" + (48*"x"))
        r = env.curl_get(url)
        assert 414 == r.response["status"]
        # nghttp sends the :method: header first (so far)
        # trigger a too long request line on it
        # the stream will RST and we get no response
        url = env.mkurl("https", "cgi", "/")
        opt = ["-H:method: {0}".format(100*"x")]
        r = env.nghttp().get(url, options=opt)
        assert r.exit_code == 0, r
        assert not r.response

    # invalid chars in method
    def test_h2_200_16(self, env):
        if not env.h2load_is_at_least('1.45.0'):
            pytest.skip(f'nhttp2 version too old')
        conf = H2Conf(env)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/hello.py")
        opt = ["-H:method: GET /hello.py"]
        r = env.nghttp().get(url, options=opt)
        assert r.exit_code == 0, r
        assert r.response is None
        url = env.mkurl("https", "cgi", "/proxy/hello.py")
        r = env.nghttp().get(url, options=opt)
        assert r.exit_code == 0, r
        assert r.response is None
