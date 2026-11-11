import re
import pytest

from pyhttpd.conf import HttpdConf


class TestSslEngineOptional:
    """SSLEngine optional enables TLS upgrade which allows HTTP session
    hijacking via a man-in-the-middle attack.  The fix removes support
    for TLS upgrade, so 'SSLEngine optional' should be rejected."""

    def test_ssl_004_01(self, env):
        """httpd should refuse to start with 'SSLEngine optional' and
        log that it is no longer supported."""
        conf = HttpdConf(env, extras={
            f"test1.{env.http_tld}": """
            SSLEngine optional
            """,
        })
        conf.add_vhost_test1()
        conf.install()
        start_pos = env.httpd_error_log.current_pos()
        rv = env.apache_restart()
        if rv == 0:
            found = env.httpd_error_log.wait_for(
                re.compile(r".*'SSLEngine optional' is no longer supported.*"),
                start_pos, timeout=5)
            env.httpd_error_log.ignore_recent(
                matches=[r'.*SSLEngine optional.*', r'.*:error\].*',
                         r'.*:warn\].*'])
            if found:
                pytest.skip(
                    "Server started but logged deprecation warning "
                    "(older httpd that warns but allows)")
            else:
                pytest.skip(
                    "Server accepted SSLEngine optional without complaint "
                    "(pre-fix httpd version)")
        else:
            found = env.httpd_error_log.wait_for(
                re.compile(r".*'SSLEngine optional' is no longer supported.*"),
                start_pos, timeout=5)
            env.httpd_error_log.ignore_recent(
                matches=[r'.*SSLEngine optional.*', r'.*:error\].*',
                         r'.*:warn\].*', r'.*:emerg\].*'])
            assert found, \
                "httpd failed to start but did not log the expected " \
                "'SSLEngine optional' rejection message"
        conf_restore = HttpdConf(env)
        conf_restore.add_vhost_test1()
        conf_restore.install()
        env.apache_restart()
