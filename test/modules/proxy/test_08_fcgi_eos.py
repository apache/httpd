"""
Tests for PR66168 / BZ 66168: a FastCGI backend that sends a premature,
stream-ending zero-length FCGI_STDOUT record and then keeps sending more
STDOUT data afterwards (as PHP-FPM does when hitting PHP bug #72185) must
not crash the worker. The extra data has to be discarded, not forwarded
down an output filter chain that already received the EOS bucket.
"""
import subprocess

import pytest

from pyhttpd.conf import HttpdConf
from .fcgi_faker import FcgiFaker, BODY_BEFORE_EOS, BODY_AFTER_EOS


FCGI_PORT = 5210


def _curl_decodes_brotli(env):
    """Whether curl can decode a brotli response (--compressed), which
    depends on how it was built: not all CI curls can."""
    try:
        out = subprocess.run([env.curl, "-V"], capture_output=True,
                             text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    for line in out.splitlines():
        if line.startswith("Features:"):
            return "brotli" in line.split()
    return False


@pytest.fixture(autouse=True, scope="class")
def _proxy_fcgi_eos_setup(env):
    faker = FcgiFaker(port=FCGI_PORT)
    faker.start()

    # The backend deliberately sends data after its own stream-ending
    # record; mod_proxy_fcgi logs AH10702 once per request when it
    # discards that data instead of crashing on it.
    env.httpd_error_log.add_ignored_lognos(["AH10702"])

    conf = HttpdConf(env)
    conf.start_vhost(
        domains=[env.d_reverse],
        port=env.http_port,
        with_ssl=False,
    )
    conf.add([
        "LogLevel proxy_fcgi:debug",
        f"ProxyPass /fcgitest fcgi://127.0.0.1:{FCGI_PORT}/",
        "AddOutputFilterByType BROTLI_COMPRESS text/plain",
    ])
    conf.end_vhost()
    conf.install()

    assert env.apache_restart() == 0

    yield

    faker.stop()


class TestProxyFcgiEos:

    def test_proxy_08_001(self, env):
        """A premature empty FCGI_STDOUT record followed by more backend
        data must not crash the worker, even with a compressing output
        filter (mod_brotli) in the chain."""
        url = f"http://{env.d_reverse}:{env.http_port}/fcgitest"
        r = env.curl_raw(url, options=["-H", "Accept-Encoding: br"])
        assert r.exit_code == 0
        assert r.response["status"] == 200
        assert r.response["header"]["content-encoding"] == "br"
        assert len(r.response["body"]) > 0

        # Check the content too where curl can decode it: everything up
        # to the premature EOS must have reached the client, but nothing
        # the backend sent after it.
        if _curl_decodes_brotli(env):
            r = env.curl_raw(url, options=["--compressed",
                                           "-H", "Accept-Encoding: br"])
            assert r.exit_code == 0
            assert r.response["status"] == 200
            assert BODY_BEFORE_EOS.decode() in r.stdout
            assert BODY_AFTER_EOS.decode() not in r.stdout

        # No segfault (or any other unexpected error/warning, e.g. AH00051)
        # was logged for this request: the package-scoped teardown asserts
        # env.check_error_log() sees nothing unaccounted for.

    def test_proxy_08_002(self, env):
        """The server (and this backend route) still answers normally
        after handling the malformed backend response above."""
        r = env.curl_raw(
            f"http://{env.d_reverse}:{env.http_port}/fcgitest")
        assert r.exit_code == 0
        assert r.response["status"] == 200
        assert BODY_BEFORE_EOS.decode() in r.stdout
        assert BODY_AFTER_EOS.decode() not in r.stdout
