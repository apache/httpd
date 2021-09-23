import pytest

from h2_conf import HttpdConf


def frame_padding(payload, padbits):
    mask = (1 << padbits) - 1
    return ((payload + 9 + mask) & ~mask) - (payload + 9)
        

class TestStore:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = HttpdConf(env)
        conf.add_vhost_cgi()
        conf.start_vhost(env.https_port, "pad0", doc_root="htdocs/cgi", with_ssl=True)
        conf.add("Protocols h2 http/1.1")
        conf.add("H2Padding 0")
        conf.add("AddHandler cgi-script .py")
        conf.end_vhost()
        conf.start_vhost(env.https_port, "pad1", doc_root="htdocs/cgi", with_ssl=True)
        conf.add("Protocols h2 http/1.1")
        conf.add("H2Padding 1")
        conf.add("AddHandler cgi-script .py")
        conf.end_vhost()
        conf.start_vhost(env.https_port, "pad2", doc_root="htdocs/cgi", with_ssl=True)
        conf.add("Protocols h2 http/1.1")
        conf.add("H2Padding 2")
        conf.add("AddHandler cgi-script .py")
        conf.end_vhost()
        conf.start_vhost(env.https_port, "pad3", doc_root="htdocs/cgi", with_ssl=True)
        conf.add("Protocols h2 http/1.1")
        conf.add("H2Padding 3")
        conf.add("AddHandler cgi-script .py")
        conf.end_vhost()
        conf.start_vhost(env.https_port, "pad8", doc_root="htdocs/cgi", with_ssl=True)
        conf.add("Protocols h2 http/1.1")
        conf.add("H2Padding 8")
        conf.add("AddHandler cgi-script .py")
        conf.end_vhost()
        conf.install()
        assert env.apache_restart() == 0

    # default paddings settings: 0 bits
    def test_104_01(self, env):
        url = env.mkurl("https", "cgi", "/echo.py")
        # we get 2 frames back: one with data and an empty one with EOF
        # check the number of padding bytes is as expected
        for data in ["x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxxxx"]:
            r = env.nghttp().post_data(url, data, 5)
            assert 200 == r.response["status"]
            assert r.results["paddings"] == [
                frame_padding(len(data)+1, 0), 
                frame_padding(0, 0)
            ]

    # 0 bits of padding
    def test_104_02(self, env):
        url = env.mkurl("https", "pad0", "/echo.py")
        for data in ["x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxxxx"]:
            r = env.nghttp().post_data(url, data, 5)
            assert 200 == r.response["status"]
            assert r.results["paddings"] == [0, 0]

    # 1 bit of padding
    def test_104_03(self, env):
        url = env.mkurl("https", "pad1", "/echo.py")
        for data in ["x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxxxx"]:
            r = env.nghttp().post_data(url, data, 5)
            assert 200 == r.response["status"]
            for i in r.results["paddings"]:
                assert i in range(0, 2)

    # 2 bits of padding
    def test_104_04(self, env):
        url = env.mkurl("https", "pad2", "/echo.py")
        for data in ["x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxxxx"]:
            r = env.nghttp().post_data(url, data, 5)
            assert 200 == r.response["status"]
            for i in r.results["paddings"]:
                assert i in range(0, 4)

    # 3 bits of padding
    def test_104_05(self, env):
        url = env.mkurl("https", "pad3", "/echo.py")
        for data in ["x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxxxx"]:
            r = env.nghttp().post_data(url, data, 5)
            assert 200 == r.response["status"]
            for i in r.results["paddings"]:
                assert i in range(0, 8)

    # 8 bits of padding
    def test_104_06(self, env):
        url = env.mkurl("https", "pad8", "/echo.py")
        for data in ["x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxxxx"]:
            r = env.nghttp().post_data(url, data, 5)
            assert 200 == r.response["status"]
            for i in r.results["paddings"]:
                assert i in range(0, 256)
