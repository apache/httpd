from datetime import timedelta

import pytest

from .env import H2Conf, H2TestEnv
from pyhttpd.curl import CurlPiper


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported, reason="mod_http2 not supported here")
class TestBuffering:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env)
        conf.add_vhost_cgi(h2proxy_self=True).install()
        assert env.apache_restart() == 0

    @pytest.mark.skip(reason="this test shows unreliable jitter")
    def test_h2_712_01(self, env):
        # test gRPC like requests that do not end, but give answers, see #207
        #
        # this test works like this:
        # - use curl to POST data to the server /h2test/echo
        # - feed curl the data in chunks, wait a bit between chunks
        # - since some buffering on curl's stdout to Python is involved,
        #   we will see the response data only at the end.
        # - therefore, we enable tracing with timestamps in curl on stderr
        #   and see when the response chunks arrive
        # - if the server sends the incoming data chunks back right away,
        #   as it should, we see receiving timestamps separated roughly by the
        #   wait time between sends.
        #
        url = env.mkurl("https", "cgi", "/h2test/echo")
        base_chunk = "0123456789"
        chunks = ["chunk-{0:03d}-{1}\n".format(i, base_chunk) for i in range(5)]
        stutter = timedelta(seconds=0.2)  # this is short, but works on my machine (tm)
        piper = CurlPiper(env=env, url=url)
        piper.stutter_check(chunks, stutter)

    def test_h2_712_02(self, env):
        # same as 712_01 but via mod_proxy_http2
        #
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/echo")
        base_chunk = "0123456789"
        chunks = ["chunk-{0:03d}-{1}\n".format(i, base_chunk) for i in range(3)]
        stutter = timedelta(seconds=0.4)  # need a bit more delay since we have the extra connection
        piper = CurlPiper(env=env, url=url)
        piper.stutter_check(chunks, stutter)

    def test_h2_712_03(self, env):
        # same as 712_02 but with smaller chunks
        #
        url = env.mkurl("https", "cgi", "/h2proxy/h2test/echo")
        base_chunk = "0"
        chunks = ["ck{0}-{1}\n".format(i, base_chunk) for i in range(3)]
        stutter = timedelta(seconds=0.4)  # need a bit more delay since we have the extra connection
        piper = CurlPiper(env=env, url=url)
        piper.stutter_check(chunks, stutter)
