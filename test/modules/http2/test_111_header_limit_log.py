import re

import pytest

from .env import H2Conf, H2TestEnv

# h2_stream_add_header() logs a limit violation once per stream, not once per
# offending header.  The guard used to be h2_stream_is_ready(), but
# set_error_response() only sets rtmp->http_status these days and never makes
# the stream "ready" while headers are still being read, so every oversized
# header logged another line.
# AH10181 is logged from the "too many headers" branch, whose only guard was
# h2_stream_is_ready().  Each header past LimitRequestFields hits it again.
LOGNO = "AH10181"
LIMIT = 5
NHEADERS = 25


@pytest.mark.skipif(condition=H2TestEnv.is_unsupported(), reason="mod_http2 not supported here")
class TestHeaderLimitLog:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = H2Conf(env, extras={
            f"test1.{env.http_tld}": [
                f"LimitRequestFields {LIMIT}",
                "LogLevel http2:info",
            ],
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_h2_111_01(self, env):
        env.httpd_error_log.clear_log()
        # Many more headers than LimitRequestFields allows.
        options = ["--http2"]
        for i in range(NHEADERS):
            options.extend(["-H", f"X-Extra-{i}: v"])
        r = env.curl_get(env.mkurl("https", "test1", "/index.html"), 5,
                         options=options)
        assert r.exit_code == 0, f"curl failed: {r.stderr}"
        assert r.response["status"] == 431, \
            f"expected 431, got {r.response['status']}"

        with open(env.httpd_error_log.path) as fd:
            hits = [ln for ln in fd if LOGNO in ln]
        assert len(hits) == 1, \
            f"{LOGNO} logged {len(hits)} times for {NHEADERS} headers over " \
            f"LimitRequestFields {LIMIT}, expected once:\n" + "".join(hits)
