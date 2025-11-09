import pytest

from .env import H2Conf, H2TestEnv


def frame_padding(payload, padbits):
    mask = (1 << padbits) - 1
    return ((payload + 9 + mask) & ~mask) - (payload + 9)
        

@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestPadding:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        def add_echo_handler(conf):
            conf.add([
                "<Location \"/h2test/echo\">",
                "    SetHandler h2test-echo",
                "</Location>",
            ])

        conf = H2Conf(env)
        conf.start_vhost(domains=[f"ssl.{env.http_tld}"], port=env.https_port, doc_root="htdocs/cgi")
        add_echo_handler(conf)
        conf.end_vhost()
        conf.start_vhost(domains=[f"pad0.{env.http_tld}"], port=env.https_port, doc_root="htdocs/cgi")
        conf.add("H2Padding 0")
        add_echo_handler(conf)
        conf.end_vhost()
        conf.start_vhost(domains=[f"pad1.{env.http_tld}"], port=env.https_port, doc_root="htdocs/cgi")
        conf.add("H2Padding 1")
        add_echo_handler(conf)
        conf.end_vhost()
        conf.start_vhost(domains=[f"pad2.{env.http_tld}"], port=env.https_port, doc_root="htdocs/cgi")
        conf.add("H2Padding 2")
        add_echo_handler(conf)
        conf.end_vhost()
        conf.start_vhost(domains=[f"pad3.{env.http_tld}"], port=env.https_port, doc_root="htdocs/cgi")
        conf.add("H2Padding 3")
        add_echo_handler(conf)
        conf.end_vhost()
        conf.start_vhost(domains=[f"pad8.{env.http_tld}"], port=env.https_port, doc_root="htdocs/cgi")
        conf.add("H2Padding 8")
        add_echo_handler(conf)
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    # default paddings settings: 0 bits
    def test_h2_104_01(self, env, repeat):
        url = env.mkurl("https", "ssl", "/h2test/echo")
        # we get 2 frames back: one with data and an empty one with EOF
        # check the number of padding bytes is as expected
        for data in ["x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxxxx"]:
            r = env.nghttp().post_data(url, data, 5)
            assert r.response["status"] == 200
            for i in r.results["paddings"]:
                assert i == frame_padding(len(data)+1, 0)

    # 0 bits of padding
    def test_h2_104_02(self, env):
        url = env.mkurl("https", "pad0", "/h2test/echo")
        for data in ["x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxxxx"]:
            r = env.nghttp().post_data(url, data, 5)
            assert r.response["status"] == 200
            for i in r.results["paddings"]:
                assert i == 0

    # 1 bit of padding
    def test_h2_104_03(self, env):
        url = env.mkurl("https", "pad1", "/h2test/echo")
        for data in ["x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxxxx"]:
            r = env.nghttp().post_data(url, data, 5)
            assert r.response["status"] == 200
            for i in r.results["paddings"]:
                assert i in range(0, 2)

    # 2 bits of padding
    def test_h2_104_04(self, env):
        url = env.mkurl("https", "pad2", "/h2test/echo")
        for data in ["x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxxxx"]:
            r = env.nghttp().post_data(url, data, 5)
            assert r.response["status"] == 200
            for i in r.results["paddings"]:
                assert i in range(0, 4)

    # 3 bits of padding
    def test_h2_104_05(self, env):
        url = env.mkurl("https", "pad3", "/h2test/echo")
        for data in ["x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxxxx"]:
            r = env.nghttp().post_data(url, data, 5)
            assert r.response["status"] == 200
            for i in r.results["paddings"]:
                assert i in range(0, 8)

    # 8 bits of padding
    def test_h2_104_06(self, env):
        url = env.mkurl("https", "pad8", "/h2test/echo")
        for data in ["x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxxxx"]:
            r = env.nghttp().post_data(url, data, 5)
            assert r.response["status"] == 200
            for i in r.results["paddings"]:
                assert i in range(0, 256)
