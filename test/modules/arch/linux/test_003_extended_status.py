import pytest

from pyhttpd.conf import HttpdConf

from .env import NO_MONITOR_TIMEOUT


class TestSystemdExtendedStatus:
    """mod_systemd turns ExtendedStatus on so that it has request counts to
    report, which changes what the rest of the server records too."""

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        yield
        conf = HttpdConf(env)
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def auto_report(self, env):
        r = env.curl_get(env.mkurl("http", "test1", "/server-status?auto"))
        assert r.response['status'] == 200
        return r.response['body'].decode()

    def install(self, env, extra=''):
        conf = HttpdConf(env, extras={
            'base': f"""
        {extra}
        <Location "/server-status">
            SetHandler server-status
        </Location>
        """
        })
        conf.add_vhost_test1()
        conf.install()
        assert env.apache_restart() == 0

    def test_systemd_003_01_enabled_by_default(self, env):
        """Loading mod_systemd is enough to get extended status; no
        ExtendedStatus directive is present in this configuration."""
        self.install(env)
        body = self.auto_report(env)
        assert 'Total Accesses:' in body, \
            "ExtendedStatus was not enabled by mod_systemd"
        assert 'Total kBytes:' in body

    def test_systemd_003_02_directive_wins(self, env):
        """An explicit ExtendedStatus off still takes effect: mod_systemd
        sets the default in pre_config, before the configuration is read."""
        self.install(env, extra='ExtendedStatus off')
        body = self.auto_report(env)
        assert 'Total Accesses:' not in body, \
            "ExtendedStatus off was overridden by mod_systemd"

    def test_systemd_003_03_no_report_without_extended_status(self, env):
        """With extended status off the monitor hook declines, so no status
        line is reported to systemd."""
        env.notify.clear()
        self.install(env, extra='ExtendedStatus off')
        # Startup notifications are still sent...
        assert env.notify.wait_for_status(r'^Processing requests\.\.\.$',
                                          timeout=10) is not None
        # ...but the periodic status line is not.
        assert env.notify.wait_for_status(r'^Total requests: ',
                                          timeout=NO_MONITOR_TIMEOUT) is None, \
            "a monitor report was sent with ExtendedStatus off"
